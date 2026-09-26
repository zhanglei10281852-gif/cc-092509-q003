"""密级调整、复核与临时解密的领域服务。

设计要点：
- 密级没有任何"管理员直接改值"的入口，所有持久化密级变更只能由
  secrecy_adjustment_requests 在满足复核条件后自动应用。
- 升级需要两名不同复核人，其中至少一人属保密办公室；降级只允许在
  专利公开后按策略建议值执行，由一名保密办公室复核人复核。
- 复核必须在 review_deadline 前完成，逾期请求由系统 sweep 标记过期，
  过期后不能再批准或应用。
- 临时解密不改变基础密级，只对绑定的查阅借阅会话在时间窗内生效，
  有效性完全由数据库时间列判定，重启后过期授权不会复活。
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.archives.repository import DossierRepository
from app.archives.secrecy_policy import LEVEL_RANK, SecrecyPolicy, normalize_level
from app.archives.validation import parse_timestamp
from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.services.audit import AuditContext, AuditService

UPGRADE_REVIEW_HOURS = 72
DOWNGRADE_REVIEW_HOURS = 120
TEMP_DECLASS_MAX_HOURS = 168

LEVEL_LABELS = {
    "internal": "内部",
    "confidential": "秘密",
    "restricted": "机密",
    "top_secret": "绝密",
}

UPGRADE_BASES = {"mass_production_escalation", "policy_revision", "incident_response"}
DOWNGRADE_BASES = {"patent_publication", "periodic_review", "policy_revision"}
ACTIVE_LOAN_STATES = ("active", "partially_returned", "overdue")


def level_label(code: str) -> str:
    return LEVEL_LABELS.get(code, code)


class SecrecyRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    # ---- 策略与项目档案 ----

    def upsert_profile(self, data: dict[str, Any], now: str) -> dict[str, Any]:
        self.connection.execute(
            """INSERT INTO secrecy_project_profiles(project_code,lifecycle_stage,secrecy_office_owner_id,note,created_at,updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(project_code) DO UPDATE SET
                   lifecycle_stage=excluded.lifecycle_stage,
                   secrecy_office_owner_id=excluded.secrecy_office_owner_id,
                   note=excluded.note,
                   updated_at=excluded.updated_at""",
            (data["project_code"], data["lifecycle_stage"], data.get("secrecy_office_owner_id"), data.get("note", ""), now, now),
        )
        return self.get_profile(data["project_code"])

    def get_profile(self, project_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM secrecy_project_profiles WHERE project_code=?", (project_code,)
        ).fetchone()
        return dict(row) if row else None

    def list_profiles(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM secrecy_project_profiles ORDER BY project_code"
        ).fetchall()]

    def upsert_rule(self, data: dict[str, Any], updated_by: int, now: str) -> dict[str, Any]:
        self.connection.execute(
            """INSERT INTO secrecy_policy_rules(project_code,asset_type,lifecycle_stage,publication_state,suggested_level,rationale,active,updated_by,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'1',?,?,?)
               ON CONFLICT(project_code,asset_type,lifecycle_stage,publication_state) DO UPDATE SET
                   suggested_level=excluded.suggested_level,
                   rationale=excluded.rationale,
                   active=1,
                   updated_by=excluded.updated_by,
                   updated_at=excluded.updated_at""",
            (
                data["project_code"], data["asset_type"], data["lifecycle_stage"],
                data["publication_state"], data["suggested_level"], data["rationale"],
                updated_by, now, now,
            ),
        )
        row = self.connection.execute(
            """SELECT * FROM secrecy_policy_rules
               WHERE project_code=? AND asset_type=? AND lifecycle_stage=? AND publication_state=?""",
            (data["project_code"], data["asset_type"], data["lifecycle_stage"], data["publication_state"]),
        ).fetchone()
        return dict(row)

    def list_rules(self, project_code: str | None = None, asset_type: str | None = None) -> list[dict[str, Any]]:
        clauses = ["active=1"]
        params: list[Any] = []
        if project_code:
            clauses.append("project_code IN ('*', ?)")
            params.append(project_code)
        if asset_type:
            clauses.append("asset_type=?")
            params.append(asset_type)
        sql = "SELECT * FROM secrecy_policy_rules WHERE " + " AND ".join(clauses)
        sql += " ORDER BY project_code,asset_type,lifecycle_stage,publication_state"
        return [dict(row) for row in self.connection.execute(sql, tuple(params)).fetchall()]

    # ---- 调整申请与复核 ----

    def insert_request(self, values: dict[str, Any], now: str) -> int:
        cursor = self.connection.execute(
            """INSERT INTO secrecy_adjustment_requests(
                   request_code,dossier_id,direction,old_level,new_level,reason,basis_code,basis_detail,
                   requested_by,state,review_deadline,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?, 'pending', ?,?,?)""",
            (
                values["request_code"], values["dossier_id"], values["direction"],
                values["old_level"], values["new_level"], values["reason"],
                values["basis_code"], values.get("basis_detail", ""), values["requested_by"],
                values["review_deadline"], now, now,
            ),
        )
        return int(cursor.lastrowid)

    def get_request(self, request_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT r.*, u.display_name AS requested_by_name
               FROM secrecy_adjustment_requests r
               JOIN users u ON u.id=r.requested_by
               WHERE r.id=?""",
            (request_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("密级调整申请不存在")
        result = dict(row)
        result["reviews"] = [
            dict(item) for item in self.connection.execute(
                """SELECT rv.*, u.display_name AS reviewer_name
                   FROM secrecy_adjustment_reviews rv JOIN users u ON u.id=rv.reviewer_user_id
                   WHERE rv.request_id=? ORDER BY rv.id""",
                (request_id,),
            ).fetchall()
        ]
        if result.get("applied_by"):
            applied = self.connection.execute(
                "SELECT display_name FROM users WHERE id=?", (result["applied_by"],)
            ).fetchone()
            result["applied_by_name"] = applied[0] if applied else None
        else:
            result["applied_by_name"] = None
        return result

    def list_requests(self, *, state: str | None = None, dossier_id: int | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if state:
            clauses.append("r.state=?")
            params.append(state)
        if dossier_id:
            clauses.append("r.dossier_id=?")
            params.append(dossier_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(100)
        rows = self.connection.execute(
            """SELECT r.*, u.display_name AS requested_by_name
               FROM secrecy_adjustment_requests r JOIN users u ON u.id=r.requested_by"""
            + where + " ORDER BY r.id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        result = [dict(row) for row in rows]
        for item in result:
            item["reviews"] = [
                dict(review) for review in self.connection.execute(
                    """SELECT rv.*, u.display_name AS reviewer_name
                       FROM secrecy_adjustment_reviews rv JOIN users u ON u.id=rv.reviewer_user_id
                       WHERE rv.request_id=? ORDER BY rv.id""",
                    (item["id"],),
                ).fetchall()
            ]
        return result

    def has_pending_for_dossier(self, dossier_id: int) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM secrecy_adjustment_requests WHERE dossier_id=? AND state='pending' LIMIT 1",
            (dossier_id,),
        ).fetchone() is not None

    def insert_review(self, request_id: int, reviewer_user_id: int, kind: str, decision: str, comment: str, now: str) -> None:
        self.connection.execute(
            """INSERT INTO secrecy_adjustment_reviews(request_id,reviewer_user_id,reviewer_kind,decision,comment,reviewed_at)
               VALUES(?,?,?,?,?,?)""",
            (request_id, reviewer_user_id, kind, decision, comment, now),
        )

    def set_request_state(self, request_id: int, state: str, now: str, *, applied_by: int | None = None) -> None:
        if state == "applied":
            self.connection.execute(
                "UPDATE secrecy_adjustment_requests SET state=?,applied_at=?,applied_by=?,version=version+1,updated_at=? WHERE id=?",
                (state, now, applied_by, now, request_id),
            )
        else:
            self.connection.execute(
                "UPDATE secrecy_adjustment_requests SET state=?,version=version+1,updated_at=? WHERE id=?",
                (state, now, request_id),
            )

    def pending_past_deadline(self, now: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM secrecy_adjustment_requests WHERE state='pending' AND review_deadline<=?",
            (now,),
        ).fetchall()]

    # ---- 历史 ----

    def insert_history(self, values: dict[str, Any], now: str) -> None:
        self.connection.execute(
            """INSERT INTO secrecy_level_history(
                   dossier_id,request_id,change_kind,old_level,new_level,effective_at,
                   reason,basis_code,actor_user_id,actor_name,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                values["dossier_id"], values.get("request_id"), values["change_kind"],
                values.get("old_level"), values["new_level"], values["effective_at"],
                values.get("reason", ""), values.get("basis_code", ""),
                values.get("actor_user_id"), values.get("actor_name", "系统"), now,
            ),
        )

    def list_history(self, dossier_id: int) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM secrecy_level_history WHERE dossier_id=? ORDER BY id",
            (dossier_id,),
        ).fetchall()]

    # ---- 临时解密 ----

    def insert_grant(self, values: dict[str, Any], now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO temporary_declassifications(
                   grant_code,dossier_id,access_loan_id,base_level,granted_by,reason,
                   starts_at,expires_at,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                values["grant_code"], values["dossier_id"], values["access_loan_id"],
                values["base_level"], values["granted_by"], values["reason"],
                values["starts_at"], values["expires_at"], now, now,
            ),
        )
        return self.get_grant(int(cursor.lastrowid))

    def get_grant(self, grant_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM temporary_declassifications WHERE id=?", (grant_id,)).fetchone()
        if row is None:
            raise NotFoundError("临时解密授权不存在")
        return dict(row)

    def active_grant_for_loan(self, dossier_id: int, access_loan_id: int, now: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT g.* FROM temporary_declassifications g
               JOIN access_loans a ON a.id=g.access_loan_id
               WHERE g.dossier_id=? AND g.access_loan_id=?
                 AND g.revoked_at IS NULL AND g.starts_at<=? AND g.expires_at>?
                 AND a.state IN ('active','partially_returned','overdue')
               ORDER BY g.id DESC LIMIT 1""",
            (dossier_id, access_loan_id, now, now),
        ).fetchone()
        return dict(row) if row else None

    def overlapping_grant(self, dossier_id: int, access_loan_id: int, now: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT * FROM temporary_declassifications
               WHERE dossier_id=? AND access_loan_id=? AND revoked_at IS NULL AND expires_at>?
               ORDER BY id DESC LIMIT 1""",
            (dossier_id, access_loan_id, now),
        ).fetchone()
        return dict(row) if row else None

    def list_grants(self, *, active_only: bool = False, now: str | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT g.*, u.display_name AS granted_by_name, a.access_code, a.state AS loan_state,"
            " a.requester_user_id, ru.display_name AS requester_name"
            " FROM temporary_declassifications g"
            " JOIN users u ON u.id=g.granted_by"
            " JOIN access_loans a ON a.id=g.access_loan_id"
            " JOIN users ru ON ru.id=a.requester_user_id"
        )
        if active_only:
            sql += (
                " WHERE g.revoked_at IS NULL AND g.starts_at<=? AND g.expires_at>?"
                " AND a.state IN ('active','partially_returned','overdue')"
            )
            rows = self.connection.execute(sql + " ORDER BY g.id DESC", (now, now)).fetchall()
        else:
            rows = self.connection.execute(sql + " ORDER BY g.id DESC").fetchall()
        return [dict(row) for row in rows]

    def grants_for_dossier(self, dossier_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT g.*, u.display_name AS granted_by_name, a.access_code, a.state AS loan_state,
                      a.requester_user_id, ru.display_name AS requester_name, a.due_at
               FROM temporary_declassifications g
               JOIN users u ON u.id=g.granted_by
               JOIN access_loans a ON a.id=g.access_loan_id
               JOIN users ru ON ru.id=a.requester_user_id
               WHERE g.dossier_id=? ORDER BY g.id""",
            (dossier_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def revoke_grant(self, grant_id: int, revoked_by: int, reason: str, now: str) -> None:
        self.connection.execute(
            "UPDATE temporary_declassifications SET revoked_at=?,revoke_reason=?,revoked_by=?,updated_at=? WHERE id=?",
            (now, reason, revoked_by, now, grant_id),
        )

    def grants_due(self, now: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM temporary_declassifications WHERE revoked_at IS NULL AND expires_at<=?",
            (now,),
        ).fetchall()]


class SecrecyService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repo = SecrecyRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.policy = SecrecyPolicy(connection)
        self.audit = AuditService(connection, self.clock)

    # ---- 策略管理 ----

    def upsert_profile(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.policy.manage")
        if data.get("secrecy_office_owner_id") is not None:
            if not self.connection.execute(
                "SELECT 1 FROM users WHERE id=? AND status='active'", (data["secrecy_office_owner_id"],)
            ).fetchone():
                raise NotFoundError("保密办公室责任人不存在或已停用")
        now = to_storage(self.clock.now())
        profile = self.repo.upsert_profile(data, now)
        self.audit.record(principal, "secrecy.profile.upsert", "secrecy_project_profile", data["project_code"], after=profile)
        return profile

    def list_profiles(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.repo.list_profiles()

    def upsert_rule(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.policy.manage")
        normalize_level(data["suggested_level"])
        now = to_storage(self.clock.now())
        rule = self.repo.upsert_rule(data, principal.user_id, now)
        self.audit.record(principal, "secrecy.rule.upsert", "secrecy_policy_rule", str(rule["id"]), after=rule)
        return rule

    def list_rules(self, principal: Principal, project_code: str | None, asset_type: str | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.repo.list_rules(project_code, asset_type)

    def suggest(self, principal: Principal, query: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.read")
        result = self.policy.suggest(
            project_code=query["project_code"],
            asset_type=query["asset_type"],
            publication_state=query.get("publication_state", "unpublished"),
            lifecycle_stage=query.get("lifecycle_stage"),
        )
        result["suggested_level_label"] = level_label(result["suggested_level"])
        return result

    # ---- 专利公开登记 ----

    def mark_patent_published(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.policy.manage")
        dossier = self.dossiers.get(dossier_id)
        if dossier["publication_state"] == "patent_published":
            raise ConflictError("档案已登记专利公开")
        published_at = parse_timestamp(data["patent_published_at"], "专利公开日")
        if published_at > self.clock.now() + timedelta(minutes=1):
            raise ValidationError("专利公开日不能晚于当前时间")
        now = to_storage(self.clock.now())
        published_storage = to_storage(published_at)
        self.connection.execute(
            "UPDATE dossiers SET publication_state='patent_published',patent_published_at=?,version=version+1,updated_at=? WHERE id=?",
            (published_storage, now, dossier_id),
        )
        after = self.dossiers.get(dossier_id)
        suggestion = self._suggestion_for(dossier_id)
        self.dossiers.append_event(
            dossier_id, "secrecy.patent_published", principal.user_id, now,
            details={"patent_published_at": published_storage, "note": data.get("note", ""), "suggested_level": suggestion["suggested_level"]},
        )
        self.audit.record(
            principal, "secrecy.patent_published", "dossier", str(dossier_id),
            before={"publication_state": dossier["publication_state"]},
            after={"publication_state": "patent_published", "patent_published_at": published_storage},
        )
        return {"dossier": after, "suggestion": suggestion}

    # ---- 密级调整申请 ----

    def create_adjustment(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.adjust.request")
        dossier = self.dossiers.get(data["dossier_id"])
        old_level = normalize_level(dossier["secrecy_level"])
        new_level = normalize_level(data["new_level"])
        if old_level == new_level:
            raise ValidationError("新密级与当前密级相同，无需调整")
        direction = "upgrade" if LEVEL_RANK[new_level] > LEVEL_RANK[old_level] else "downgrade"
        if self.repo.has_pending_for_dossier(dossier["id"]):
            raise ConflictError("该档案已有待复核的密级调整申请")
        now_dt = self.clock.now()
        if direction == "upgrade":
            if dossier["publication_state"] == "patent_published":
                raise ConflictError("专利已公开的技术不再允许升级密级")
            if data["basis_code"] not in UPGRADE_BASES:
                raise ValidationError("升级密级的依据只能是量产升高、制度修订或事件响应")
            deadline = now_dt + timedelta(hours=UPGRADE_REVIEW_HOURS)
            required_note = "升级需两名不同复核人，其中至少一人属保密办公室"
        else:
            if dossier["publication_state"] != "patent_published":
                raise ConflictError("专利公开前不允许主动降级密级")
            if data["basis_code"] not in DOWNGRADE_BASES:
                raise ValidationError("降级密级的依据只能是专利公开、定期复核或制度修订")
            suggestion = self._suggestion_for(dossier["id"])
            if new_level != suggestion["suggested_level"]:
                raise ConflictError(
                    "降级目标必须等于当前策略建议密级",
                    context={"suggested_level": suggestion["suggested_level"]},
                )
            deadline = now_dt + timedelta(hours=DOWNGRADE_REVIEW_HOURS)
            required_note = "降级需一名保密办公室复核人复核"
        if data.get("review_deadline"):
            deadline = parse_timestamp(data["review_deadline"], "复核期限")
            max_window = UPGRADE_REVIEW_HOURS if direction == "upgrade" else DOWNGRADE_REVIEW_HOURS
            if deadline <= now_dt:
                raise ValidationError("复核期限必须晚于当前时间")
            if deadline > now_dt + timedelta(hours=max_window):
                direction_label = "升级" if direction == "upgrade" else "降级"
                raise ValidationError(f"{direction_label}复核期限不能超过 {max_window} 小时")
        request_code = f"SCL-{uuid.uuid4().hex[:12]}"
        request_id = self.repo.insert_request(
            {
                "request_code": request_code,
                "dossier_id": dossier["id"],
                "direction": direction,
                "old_level": old_level,
                "new_level": new_level,
                "reason": data["reason"],
                "basis_code": data["basis_code"],
                "basis_detail": data.get("basis_detail", ""),
                "requested_by": principal.user_id,
                "review_deadline": to_storage(deadline),
            },
            to_storage(now_dt),
        )
        request = self.repo.get_request(request_id)
        self.audit.record(
            principal, "secrecy.adjustment.request", "secrecy_adjustment_request", str(request_id),
            after={**request, "approval_rule": required_note},
        )
        return request

    def review_adjustment(self, principal: Principal, request_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.review")
        request = self.repo.get_request(request_id)
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        if request["state"] != "pending":
            raise ConflictError(f"申请当前状态为 {request['state']}，不能再复核")
        if request["review_deadline"] <= now:
            # 不在回滚事务里改写状态；逾期请求由 sweep_expired 统一落库。
            raise ConflictError("已超过复核期限，申请不能再复核，将由系统标记过期")
        if request["requested_by"] == principal.user_id:
            raise ValidationError("申请人不能复核自己的密级调整申请")
        if any(review["reviewer_user_id"] == principal.user_id for review in request["reviews"]):
            raise ConflictError("同一复核人不能重复复核")
        is_office = principal.can("secrecy.office")
        if request["direction"] == "downgrade" and not is_office:
            raise PermissionDeniedError("降级复核必须由保密办公室成员完成")
        decision = data["decision"]
        kind = "secrecy_office" if is_office else "peer"
        self.repo.insert_review(request_id, principal.user_id, kind, decision, data.get("comment", ""), now)
        if decision == "reject":
            self.repo.set_request_state(request_id, "rejected", now)
            result = self.repo.get_request(request_id)
            self._record_review_audit(principal, request_id, result)
            return result
        if request["direction"] == "downgrade":
            result = self._apply_adjustment(request_id, principal, now)
            self._record_review_audit(principal, request_id, result)
            return result
        # 升级：累计两名不同复核人，且至少一人来自保密办公室。
        reviews = self.repo.get_request(request_id)["reviews"]
        office_approved = any(review["reviewer_kind"] == "secrecy_office" for review in reviews)
        if len(reviews) >= 2 and office_approved:
            result = self._apply_adjustment(request_id, principal, now)
        else:
            pending = []
            if len(reviews) < 2:
                pending.append("等待第二名不同复核人")
            if not office_approved:
                pending.append("其中至少一人须属保密办公室")
            result = self.repo.get_request(request_id)
            result["pending_requirements"] = pending
        self._record_review_audit(principal, request_id, result)
        return result

    def _apply_adjustment(self, request_id: int, principal: Principal, now: str) -> dict[str, Any]:
        request = self.repo.get_request(request_id)
        dossier = self.dossiers.get(request["dossier_id"])
        if dossier["secrecy_level"] != request["old_level"]:
            raise ConflictError("档案密级在复核期间已被其他调整改变，请重新发起申请")
        self.connection.execute(
            "UPDATE dossiers SET secrecy_level=?,version=version+1,updated_at=? WHERE id=?",
            (request["new_level"], now, request["dossier_id"]),
        )
        self.repo.set_request_state(request_id, "applied", now, applied_by=principal.user_id)
        self.repo.insert_history(
            {
                "dossier_id": request["dossier_id"],
                "request_id": request_id,
                "change_kind": request["direction"],
                "old_level": request["old_level"],
                "new_level": request["new_level"],
                "effective_at": now,
                "reason": request["reason"],
                "basis_code": request["basis_code"],
                "actor_user_id": principal.user_id,
                "actor_name": principal.display_name,
            },
            now,
        )
        self.dossiers.append_event(
            request["dossier_id"], f"secrecy.{request['direction']}", principal.user_id, now,
            details={
                "request_id": request_id,
                "old_level": request["old_level"],
                "new_level": request["new_level"],
                "basis_code": request["basis_code"],
            },
        )
        return self.repo.get_request(request_id)

    def _record_review_audit(self, principal: Principal, request_id: int, result: dict[str, Any]) -> None:
        self.audit.record(
            principal, "secrecy.adjustment.review", "secrecy_adjustment_request", str(request_id), after=result
        )

    def list_adjustments(self, principal: Principal, state: str | None, dossier_id: int | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.repo.list_requests(state=state, dossier_id=dossier_id)

    # ---- 临时解密 ----

    def grant_temporary_declassification(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.declassify")
        dossier = self.dossiers.get(data["dossier_id"])
        loan = self._get_loan(data["access_loan_id"])
        if loan["dossier_id"] != dossier["id"]:
            raise ValidationError("查阅会话不属于该档案")
        if loan["state"] not in ACTIVE_LOAN_STATES:
            raise ConflictError("查阅会话已结束，不能在其上授予临时解密")
        if dossier["secrecy_level"] == "internal":
            raise ConflictError("内部资料无需临时解密")
        now_dt = self.clock.now()
        starts_dt = parse_timestamp(data["starts_at"], "生效时间") if data.get("starts_at") else now_dt
        expires_dt = parse_timestamp(data["expires_at"], "失效时间")
        if starts_dt < now_dt - timedelta(seconds=1):
            raise ValidationError("临时解密生效时间不能早于当前时间")
        if expires_dt <= starts_dt:
            raise ValidationError("失效时间必须晚于生效时间")
        if expires_dt > starts_dt + timedelta(hours=TEMP_DECLASS_MAX_HOURS):
            raise ValidationError(f"临时解密最长 {TEMP_DECLASS_MAX_HOURS} 小时")
        due_at = parse_timestamp(loan["due_at"], "查阅到期时间")
        if expires_dt > due_at:
            raise ConflictError("临时解密不能晚于查阅会话到期时间", context={"loan_due_at": loan["due_at"]})
        if data.get("expected_base_level") and data["expected_base_level"] != dossier["secrecy_level"]:
            raise ConflictError("基础密级已变化，请刷新后重试")
        if self.repo.overlapping_grant(dossier["id"], loan["id"], to_storage(now_dt)):
            raise ConflictError("该查阅会话已存在未失效的临时解密授权")
        grant = self.repo.insert_grant(
            {
                "grant_code": f"TMP-{uuid.uuid4().hex[:12]}",
                "dossier_id": dossier["id"],
                "access_loan_id": loan["id"],
                "base_level": dossier["secrecy_level"],
                "granted_by": principal.user_id,
                "reason": data["reason"],
                "starts_at": to_storage(starts_dt),
                "expires_at": to_storage(expires_dt),
            },
            to_storage(now_dt),
        )
        self.repo.insert_history(
            {
                "dossier_id": dossier["id"],
                "change_kind": "temporary_decrypt",
                "old_level": dossier["secrecy_level"],
                "new_level": "internal",
                "effective_at": to_storage(starts_dt),
                "reason": f"临时解密（{grant['grant_code']}）：{data['reason']}",
                "basis_code": "temporary_session_decrypt",
                "actor_user_id": principal.user_id,
                "actor_name": principal.display_name,
            },
            to_storage(now_dt),
        )
        self.audit.record(
            principal, "secrecy.temporary_grant", "temporary_declassification", str(grant["id"]),
            after=grant, metadata={"access_loan_id": loan["id"]},
        )
        return grant

    def revoke_temporary_declassification(self, principal: Principal, grant_id: int, reason: str) -> dict[str, Any]:
        principal.require("secrecy.declassify")
        grant = self.repo.get_grant(grant_id)
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        if grant["revoked_at"] is not None:
            raise ConflictError("临时解密授权已失效")
        was_effective = grant["starts_at"] <= now
        self.repo.revoke_grant(grant_id, principal.user_id, reason, now)
        if was_effective:
            self.repo.insert_history(
                {
                    "dossier_id": grant["dossier_id"],
                    "change_kind": "temp_decrypt_revoked",
                    "old_level": "internal",
                    "new_level": grant["base_level"],
                    "effective_at": now,
                    "reason": f"人工撤销（{grant['grant_code']}）：{reason}",
                    "basis_code": "temporary_session_decrypt",
                    "actor_user_id": principal.user_id,
                    "actor_name": principal.display_name,
                },
                now,
            )
        result = self.repo.get_grant(grant_id)
        self.audit.record(
            principal, "secrecy.temporary_revoke", "temporary_declassification", str(grant_id),
            before=grant, after=result, metadata={"reason": reason, "was_effective": was_effective},
        )
        return result

    def list_grants(self, principal: Principal, active_only: bool) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        now = to_storage(self.clock.now())
        grants = self.repo.list_grants(active_only=active_only, now=now)
        for grant in grants:
            grant["effective_now"] = self._grant_effective(grant, now)
        return grants

    def effective_level(self, principal: Principal, dossier_id: int, access_loan_id: int | None) -> dict[str, Any]:
        principal.require("dossiers.read")
        dossier = self.dossiers.get(dossier_id)
        now = to_storage(self.clock.now())
        response: dict[str, Any] = {
            "dossier_id": dossier_id,
            "base_level": dossier["secrecy_level"],
            "base_level_label": level_label(dossier["secrecy_level"]),
            "effective_level": dossier["secrecy_level"],
            "effective_level_label": level_label(dossier["secrecy_level"]),
            "publication_state": dossier["publication_state"],
            "at": now,
            "temporary_grant": None,
        }
        if access_loan_id is not None:
            grant = self.repo.active_grant_for_loan(dossier_id, access_loan_id, now)
            if grant is not None:
                response["effective_level"] = "internal"
                response["effective_level_label"] = level_label("internal")
                response["temporary_grant"] = {
                    "grant_id": grant["id"],
                    "grant_code": grant["grant_code"],
                    "access_loan_id": grant["access_loan_id"],
                    "starts_at": grant["starts_at"],
                    "expires_at": grant["expires_at"],
                }
        return response

    # ---- 历史与仍在使用的会话 ----

    def history(self, principal: Principal, dossier_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        dossier = self.dossiers.get(dossier_id)
        now = to_storage(self.clock.now())
        suggestion = self._suggestion_for(dossier_id)
        grants = self.repo.grants_for_dossier(dossier_id)
        active_sessions = []
        for grant in grants:
            effective = self._grant_effective(grant, now)
            active_sessions.append(
                {
                    "grant_id": grant["id"],
                    "grant_code": grant["grant_code"],
                    "access_loan_id": grant["access_loan_id"],
                    "access_code": grant["access_code"],
                    "loan_state": grant["loan_state"],
                    "requester_user_id": grant["requester_user_id"],
                    "requester_name": grant["requester_name"],
                    "granted_by_name": grant["granted_by_name"],
                    "starts_at": grant["starts_at"],
                    "expires_at": grant["expires_at"],
                    "revoked_at": grant["revoked_at"],
                    "revoke_reason": grant["revoke_reason"],
                    "in_use": effective,
                }
            )
        history = self.repo.list_history(dossier_id)
        for item in history:
            item["old_level_label"] = level_label(item["old_level"]) if item["old_level"] else None
            item["new_level_label"] = level_label(item["new_level"])
        return {
            "dossier_id": dossier_id,
            "dossier_code": dossier["dossier_code"],
            "current": {
                "base_level": dossier["secrecy_level"],
                "base_level_label": level_label(dossier["secrecy_level"]),
                "publication_state": dossier["publication_state"],
                "patent_published_at": dossier["patent_published_at"],
                "suggested_level": suggestion["suggested_level"],
                "suggested_level_label": level_label(suggestion["suggested_level"]),
                "suggestion_rationale": suggestion["rationale"],
            },
            "history": history,
            "requests": self.repo.list_requests(dossier_id=dossier_id),
            "temporary_sessions": active_sessions,
            "active_sessions": [session for session in active_sessions if session["in_use"]],
        }

    # ---- 内部辅助 ----

    def _get_loan(self, access_loan_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM access_loans WHERE id=?", (access_loan_id,)).fetchone()
        if row is None:
            raise NotFoundError("查阅借阅会话不存在")
        return dict(row)

    def _suggestion_for(self, dossier_id: int) -> dict[str, Any]:
        dossier = self.dossiers.get(dossier_id)
        batch = self.connection.execute(
            "SELECT project_code FROM intake_batches WHERE id=?", (dossier["intake_id"],)
        ).fetchone()
        return self.policy.suggest(
            project_code=batch["project_code"],
            asset_type=dossier["asset_type"],
            publication_state=dossier["publication_state"],
        )

    def _grant_effective(self, grant: dict[str, Any], now: str) -> bool:
        return (
            grant["revoked_at"] is None
            and grant["starts_at"] <= now < grant["expires_at"]
            and grant["loan_state"] in ACTIVE_LOAN_STATES
        )


def sweep_expired(connection: sqlite3.Connection, clock: Clock | None = None) -> dict[str, int]:
    """将过期的临时解密与超期未复核的申请标记失效。

    纯时间判定，不依赖任何进程内状态，因此服务重启后重复执行也是安全的。
    """
    clock = clock or SystemClock()
    now = to_storage(clock.now())
    repo = SecrecyRepository(connection)
    audit = AuditService(connection, clock)
    expired_grants = 0
    for grant in repo.grants_due(now):
        repo.revoke_grant(grant["id"], None, "expired_system", now)
        repo.insert_history(
            {
                "dossier_id": grant["dossier_id"],
                "change_kind": "temp_decrypt_expired",
                "old_level": "internal",
                "new_level": grant["base_level"],
                "effective_at": now,
                "reason": f"临时解密到期自动失效（{grant['grant_code']}）",
                "basis_code": "temporary_session_decrypt",
                "actor_user_id": None,
                "actor_name": "系统",
            },
            now,
        )
        audit.record(
            AuditContext(None, "系统"),
            action="secrecy.temporary_expired",
            resource_type="temporary_declassification",
            resource_id=grant["id"],
            metadata={"grant_code": grant["grant_code"], "access_loan_id": grant["access_loan_id"]},
        )
        expired_grants += 1
    expired_requests = 0
    for request in repo.pending_past_deadline(now):
        repo.set_request_state(request["id"], "expired", now)
        audit.record(
            AuditContext(None, "系统"),
            action="secrecy.adjustment.expired",
            resource_type="secrecy_adjustment_request",
            resource_id=request["id"],
            metadata={"review_deadline": request["review_deadline"]},
        )
        expired_requests += 1
    return {"expired_grants": expired_grants, "expired_requests": expired_requests}
