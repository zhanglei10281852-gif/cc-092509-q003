"""密级策略、密级调整复核与临时解密授权。

密级只能通过两条路径变化：

1. ``secrecy_adjustments`` 审批流——升级需两名持升级复核权限的人员在限期内
   分别同意，降级需一名持降级复核权限的人员同意，且目标必须等于制度建议密级；
2. ``temporary_declassifications``——只对指定登录查阅会话生效、到期自动失效，
   有效性完全由数据库中的时间窗与会话状态实时判定，服务重启不会让已过期的
   授权复活。

系统不存在直接改写 ``dossiers.secrecy_level`` 的接口，任何角色（含管理员）
都不能绕过复核直接修改结果。
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.archives.repository import DossierRepository
from app.archives.validation import parse_timestamp
from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.services.audit import AuditService

LEVEL_RANK = {"internal": 0, "confidential": 1, "restricted": 2, "top_secret": 3}
STAGES = ("research", "production", "patent_published")

UPGRADE_REQUIRED_REVIEWS = 2
DOWNGRADE_REQUIRED_REVIEWS = 1
UPGRADE_DEADLINE_HOURS = 48
DOWNGRADE_DEADLINE_HOURS = 72
MAX_TEMP_DECLASS_HOURS = 24 * 7


def derive_stage(dossier: dict[str, Any], now_iso: str) -> str:
    """依据量产时间与专利公开日推导公开状态；公开日到达后才视为公开。"""
    published_at = dossier.get("patent_published_at")
    if published_at and published_at <= now_iso:
        return "patent_published"
    production_at = dossier.get("production_started_at")
    if production_at and production_at <= now_iso:
        return "production"
    return "research"


class SecrecyPolicyService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.audit = AuditService(connection, self.clock)

    def create_policy(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.policy.manage")
        if self.connection.execute(
            "SELECT id FROM secrecy_policies WHERE policy_code=?", (data["policy_code"],)
        ).fetchone():
            raise ConflictError("策略编码已经存在")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            """INSERT INTO secrecy_policies(
                   policy_code,project_code,asset_type,stage,suggested_level,basis,priority,active,created_by,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,1,?,?,?)""",
            (
                data["policy_code"], data["project_code"], data["asset_type"], data["stage"],
                data["suggested_level"], data["basis"], data["priority"], principal.user_id, now, now,
            ),
        )
        policy = self.get_policy(cursor.lastrowid)
        self.audit.record(principal, "secrecy.policy.create", "secrecy_policy", policy["id"], after=policy)
        return policy

    def get_policy(self, policy_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM secrecy_policies WHERE id=?", (policy_id,)).fetchone()
        if row is None:
            raise NotFoundError("密级策略不存在")
        return dict(row)

    def list_policies(self, principal: Principal, active_only: bool = True) -> list[dict[str, Any]]:
        principal.require("secrecy.read")
        sql = "SELECT * FROM secrecy_policies"
        if active_only:
            sql += " WHERE active=1"
        sql += " ORDER BY priority,id"
        return [dict(row) for row in self.connection.execute(sql).fetchall()]

    def match(self, project_code: str, asset_type: str, stage: str) -> dict[str, Any] | None:
        """返回最具体的生效策略；同具体度时 priority 小者优先。"""
        rows = self.connection.execute(
            "SELECT * FROM secrecy_policies WHERE active=1 AND stage IN ('any',?)", (stage,)
        ).fetchall()
        candidates = []
        for row in rows:
            item = dict(row)
            if item["project_code"] not in {"*", project_code}:
                continue
            if item["asset_type"] not in {"*", asset_type}:
                continue
            specificity = (
                (2 if item["project_code"] == project_code else 0)
                + (2 if item["asset_type"] == asset_type else 0)
                + (2 if item["stage"] == stage else 0)
            )
            candidates.append((specificity, item))
        if not candidates:
            return None
        candidates.sort(key=lambda pair: (-pair[0], pair[1]["priority"], pair[1]["id"]))
        return candidates[0][1]

    def suggest(self, principal: Principal, project_code: str, asset_type: str, stage: str) -> dict[str, Any]:
        principal.require("secrecy.read")
        if stage not in STAGES:
            raise ValidationError("公开状态必须是 research、production 或 patent_published")
        policy = self.match(project_code, asset_type, stage)
        return {
            "project_code": project_code,
            "asset_type": asset_type,
            "stage": stage,
            "suggested_level": policy["suggested_level"] if policy else None,
            "matched_policy": policy,
        }


class SecrecyAdjustmentService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.policies = SecrecyPolicyService(connection, clock)
        self.audit = AuditService(connection, self.clock)

    # -- 建议密级（按项目、资产类型、公开状态） --------------------------------

    def suggestion_for_dossier(self, principal: Principal, dossier_id: int) -> dict[str, Any]:
        principal.require("secrecy.read")
        dossier = self.dossiers.get(dossier_id)
        batch = self.connection.execute(
            "SELECT project_code FROM intake_batches WHERE id=?", (dossier["intake_id"],)
        ).fetchone()
        now_iso = to_storage(self.clock.now())
        stage = derive_stage(dossier, now_iso)
        policy = self.policies.match(batch["project_code"], dossier["asset_type"], stage)
        return {
            "dossier_id": dossier_id,
            "project_code": batch["project_code"],
            "asset_type": dossier["asset_type"],
            "stage": stage,
            "current_level": dossier["secrecy_level"],
            "suggested_level": policy["suggested_level"] if policy else None,
            "matched_policy": policy,
        }

    def mark_stage(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        """登记量产时间或专利公开日（公开状态事实），不直接改变密级。"""
        principal.require("secrecy.adjust")
        dossier = self.dossiers.get(dossier_id)
        now = to_storage(self.clock.now())
        normalized: dict[str, str | None] = {}
        for field in ("production_started_at", "patent_published_at"):
            if data.get(field) is not None:
                normalized[field] = to_storage(parse_timestamp(data[field], field))
        cursor = self.connection.execute(
            """UPDATE dossiers
               SET production_started_at=COALESCE(?,production_started_at),
                   patent_published_at=COALESCE(?,patent_published_at),
                   version=version+1,updated_at=?
               WHERE id=?""",
            (normalized.get("production_started_at"), normalized.get("patent_published_at"), now, dossier_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("公开状态更新失败")
        after = self.dossiers.get(dossier_id)
        self.dossiers.append_event(
            dossier_id, "secrecy.stage_marked", principal.user_id, now,
            details={
                "production_started_at": after["production_started_at"],
                "patent_published_at": after["patent_published_at"],
                "note": data.get("note", ""),
            },
        )
        self.audit.record(
            principal, "secrecy.stage_mark", "dossier", str(dossier_id),
            before={"production_started_at": dossier["production_started_at"],
                    "patent_published_at": dossier["patent_published_at"]},
            after={"production_started_at": after["production_started_at"],
                   "patent_published_at": after["patent_published_at"]},
        )
        return after

    # -- 调整申请与复核 -------------------------------------------------------

    def request_adjustment(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.adjust")
        dossier = self.dossiers.get(dossier_id)
        batch = self.connection.execute(
            "SELECT project_code FROM intake_batches WHERE id=?", (dossier["intake_id"],)
        ).fetchone()
        now_dt = self.clock.now()
        now_iso = to_storage(now_dt)
        stage = derive_stage(dossier, now_iso)
        policy = self.policies.match(batch["project_code"], dossier["asset_type"], stage)
        suggested = policy["suggested_level"] if policy else None
        target = data.get("to_level") or suggested
        if target is None:
            raise ValidationError("当前没有匹配的密级策略，必须显式填写目标密级")
        current = dossier["secrecy_level"]
        if target == current:
            raise ValidationError("目标密级与当前密级相同，无需调整")
        direction = "upgrade" if LEVEL_RANK[target] > LEVEL_RANK[current] else "downgrade"
        if direction == "downgrade" and target != suggested:
            raise ValidationError(
                "降级目标必须等于制度建议密级",
                context={"suggested_level": suggested, "stage": stage},
            )
        deadline_text = data.get("review_deadline")
        if deadline_text:
            deadline = parse_timestamp(deadline_text, "复核期限")
            if deadline <= now_dt:
                raise ValidationError("复核期限必须晚于当前时间")
        else:
            hours = UPGRADE_DEADLINE_HOURS if direction == "upgrade" else DOWNGRADE_DEADLINE_HOURS
            deadline = now_dt + timedelta(hours=hours)
        required = UPGRADE_REQUIRED_REVIEWS if direction == "upgrade" else DOWNGRADE_REQUIRED_REVIEWS
        basis = policy["basis"] if policy else "申请人工指定（无匹配策略）"
        code = f"SEC-ADJ-{uuid.uuid4().hex[:12]}"
        cursor = self.connection.execute(
            """INSERT INTO secrecy_adjustments(
                   adjustment_code,dossier_id,direction,from_level,to_level,reason,basis,
                   requested_by,requested_at,review_deadline,state,policy_id,required_reviews,
                   created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?)""",
            (
                code, dossier_id, direction, current, target, data["reason"], basis,
                principal.user_id, now_iso, to_storage(deadline), policy["id"] if policy else None,
                required, now_iso, now_iso,
            ),
        )
        adjustment = self.get_adjustment(cursor.lastrowid)
        self.dossiers.append_event(
            dossier_id, "secrecy.adjustment_requested", principal.user_id, now_iso,
            details={
                "adjustment_id": adjustment["id"], "direction": direction,
                "from_level": current, "to_level": target,
                "review_deadline": to_storage(deadline), "required_reviews": required,
            },
        )
        self.audit.record(
            principal, "secrecy.adjustment.request", "secrecy_adjustment", adjustment["id"], after=adjustment
        )
        return adjustment

    def decide(self, principal: Principal, adjustment_id: int, data: dict[str, Any]) -> dict[str, Any]:
        adjustment = self._expire_if_overdue(adjustment_id)
        if adjustment["state"] != "pending":
            raise ConflictError(f"密级调整申请已经结束：{adjustment['state']}")
        permission = (
            "secrecy.review_upgrade" if adjustment["direction"] == "upgrade"
            else "secrecy.review_downgrade"
        )
        principal.require(permission)
        if adjustment["requested_by"] == principal.user_id:
            raise ValidationError("申请人不能复核自己发起的密级调整")
        now_dt = self.clock.now()
        now_iso = to_storage(now_dt)
        already = self.connection.execute(
            "SELECT id FROM secrecy_adjustment_reviews WHERE adjustment_id=? AND reviewer_user_id=?",
            (adjustment_id, principal.user_id),
        ).fetchone()
        if already:
            raise ConflictError("该复核人已经签署过意见")
        before = dict(adjustment)
        self.connection.execute(
            """INSERT INTO secrecy_adjustment_reviews(adjustment_id,reviewer_user_id,decision,comment,reviewed_at)
               VALUES(?,?,?,?,?)""",
            (adjustment_id, principal.user_id, data["decision"], data.get("comment", ""), now_iso),
        )
        if data["decision"] == "reject":
            self.connection.execute(
                "UPDATE secrecy_adjustments SET state='rejected',reviewed_at=?,reviewed_by=?,"
                "review_comment=?,version=version+1,updated_at=? WHERE id=?",
                (now_iso, principal.user_id, data.get("comment", ""), now_iso, adjustment_id),
            )
            result = self.get_adjustment(adjustment_id)
            self.audit.record(principal, "secrecy.adjustment.reject", "secrecy_adjustment", adjustment_id,
                              before=before, after=result)
            return result
        approvals = self.connection.execute(
            "SELECT COUNT(*) FROM secrecy_adjustment_reviews WHERE adjustment_id=? AND decision='approve'",
            (adjustment_id,),
        ).fetchone()[0]
        if approvals >= adjustment["required_reviews"]:
            self._apply_effect(adjustment, principal, now_iso)
        else:
            self.connection.execute(
                "UPDATE secrecy_adjustments SET version=version+1,updated_at=? WHERE id=?",
                (now_iso, adjustment_id),
            )
        result = self.get_adjustment(adjustment_id)
        self.audit.record(principal, "secrecy.adjustment.approve", "secrecy_adjustment", adjustment_id,
                          before=before, after=result,
                          metadata={"approvals": approvals, "required_reviews": adjustment["required_reviews"]})
        return result

    def _apply_effect(self, adjustment: dict[str, Any], principal: Principal, now_iso: str) -> None:
        dossier = self.dossiers.get(adjustment["dossier_id"])
        if dossier["secrecy_level"] != adjustment["from_level"]:
            raise ConflictError("档案密级在复核期间已发生变化，本次调整失效")
        if adjustment["direction"] == "downgrade":
            batch = self.connection.execute(
                "SELECT project_code FROM intake_batches WHERE id=?", (dossier["intake_id"],)
            ).fetchone()
            stage = derive_stage(dossier, now_iso)
            policy = self.policies.match(batch["project_code"], dossier["asset_type"], stage)
            suggested = policy["suggested_level"] if policy else None
            if suggested != adjustment["to_level"]:
                raise ConflictError(
                    "制度建议密级已变化，不能按原申请降级",
                    context={"suggested_level": suggested},
                )
        cursor = self.connection.execute(
            """UPDATE dossiers SET secrecy_level=?,version=version+1,updated_at=? WHERE id=?""",
            (adjustment["to_level"], now_iso, adjustment["dossier_id"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("密级生效失败")
        self.connection.execute(
            """UPDATE secrecy_adjustments
               SET state='approved',reviewed_at=?,reviewed_by=?,effective_at=?,version=version+1,updated_at=?
               WHERE id=?""",
            (now_iso, principal.user_id, now_iso, now_iso, adjustment["id"]),
        )
        self.dossiers.append_event(
            adjustment["dossier_id"], "secrecy.changed", principal.user_id, now_iso,
            from_state=adjustment["from_level"], to_state=adjustment["to_level"],
            details={
                "adjustment_id": adjustment["id"], "direction": adjustment["direction"],
                "basis": adjustment["basis"], "effective_at": now_iso,
            },
        )

    def get_adjustment(self, adjustment_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM secrecy_adjustments WHERE id=?", (adjustment_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("密级调整申请不存在")
        return self._hydrate(dict(row))

    def _hydrate(self, adjustment: dict[str, Any]) -> dict[str, Any]:
        adjustment["reviews"] = [
            dict(row) for row in self.connection.execute(
                """SELECT r.*,u.username,u.display_name AS reviewer_name
                   FROM secrecy_adjustment_reviews r JOIN users u ON u.id=r.reviewer_user_id
                   WHERE r.adjustment_id=? ORDER BY r.id""",
                (adjustment["id"],),
            ).fetchall()
        ]
        requester = self.connection.execute(
            "SELECT username,display_name FROM users WHERE id=?", (adjustment["requested_by"],)
        ).fetchone()
        adjustment["requested_by_name"] = dict(requester)["display_name"] if requester else None
        return adjustment

    def _expire_if_overdue(self, adjustment_id: int) -> dict[str, Any]:
        adjustment = self.get_adjustment(adjustment_id)
        now_iso = to_storage(self.clock.now())
        if adjustment["state"] == "pending" and adjustment["review_deadline"] < now_iso:
            self.connection.execute(
                "UPDATE secrecy_adjustments SET state='expired',version=version+1,updated_at=? WHERE id=? AND state='pending'",
                (now_iso, adjustment_id),
            )
            self.dossiers.append_event(
                adjustment["dossier_id"], "secrecy.adjustment_expired", None, now_iso,
                details={"adjustment_id": adjustment_id, "review_deadline": adjustment["review_deadline"]},
            )
            self.audit.record(
                _SystemActor(), "secrecy.adjustment.expire", "secrecy_adjustment", adjustment_id,
                after={"state": "expired"},
            )
            adjustment = self.get_adjustment(adjustment_id)
        return adjustment

    def sweep_expired(self, principal: Principal | None = None) -> dict[str, Any]:
        if principal is not None:
            principal.require("secrecy.read")
        now_iso = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id FROM secrecy_adjustments WHERE state='pending' AND review_deadline<?",
            (now_iso,),
        ).fetchall()
        expired_ids = []
        for row in rows:
            self._expire_if_overdue(row["id"])
            expired_ids.append(row["id"])
        return {"expired_adjustment_ids": expired_ids, "count": len(expired_ids)}

    def history(self, principal: Principal, dossier_id: int) -> dict[str, Any]:
        principal.require("secrecy.read")
        self.dossiers.get(dossier_id)
        self.sweep_expired()
        now_iso = to_storage(self.clock.now())
        rows = self.connection.execute(
            """SELECT * FROM secrecy_adjustments WHERE dossier_id=? ORDER BY id""",
            (dossier_id,),
        ).fetchall()
        adjustments = [self._hydrate(dict(row)) for row in rows]
        now_dt = self.clock.now()
        all_grants = self._list_grants(dossier_id)
        for grant in all_grants:
            grant["status"] = self._grant_status(grant, now_dt)
        active_grants = [grant for grant in all_grants if grant["status"] == "active"]
        dossier = self.dossiers.get(dossier_id)
        return {
            "dossier_id": dossier_id,
            "current_level": dossier["secrecy_level"],
            "adjustments": adjustments,
            "active_temporary_declassifications": active_grants,
            "temporary_declassifications": all_grants,
            "checked_at": now_iso,
        }

    def _list_grants(self, dossier_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                """SELECT t.*,su.display_name AS granted_by_name,
                          u.id AS session_user_id,u.username AS session_username,
                          u.display_name AS session_user_name,s.client_label,
                          s.revoked_at AS session_revoked_at,
                          s.expires_at AS session_expires_at
                   FROM temporary_declassifications t
                   JOIN sessions s ON s.id=t.access_session_id
                   JOIN users u ON u.id=s.user_id
                   JOIN users su ON su.id=t.granted_by
                   WHERE t.dossier_id=? ORDER BY t.id""",
                (dossier_id,),
            ).fetchall()
        ]

    @staticmethod
    def _grant_status(grant: dict[str, Any], now_dt) -> str:
        from app.core.clock import from_storage

        if grant["revoked_at"] is not None:
            return "revoked"
        if grant["session_revoked_at"] is not None:
            return "session_revoked"
        if from_storage(grant["expires_at"]) <= now_dt:
            return "expired"
        if from_storage(grant["session_expires_at"]) <= now_dt:
            return "session_expired"
        return "active"


class _SystemActor:
    user_id = None
    display_name = "保密办公室定时任务"


class TemporaryDeclassificationService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.adjustments = SecrecyAdjustmentService(connection, clock)
        self.audit = AuditService(connection, self.clock)

    def grant(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("secrecy.temp_declass")
        dossier = self.dossiers.get(dossier_id)
        now_dt = self.clock.now()
        expires = parse_timestamp(data["expires_at"], "到期时间")
        if expires <= now_dt:
            raise ValidationError("临时解密到期时间必须晚于当前时间")
        if expires > now_dt + timedelta(hours=MAX_TEMP_DECLASS_HOURS):
            raise ValidationError(f"临时解密最长授权 {MAX_TEMP_DECLASS_HOURS // 24} 天")
        session = self.connection.execute(
            "SELECT * FROM sessions WHERE id=?", (data["access_session_id"],)
        ).fetchone()
        if session is None:
            raise NotFoundError("指定的查阅会话不存在")
        session = dict(session)
        if session["revoked_at"] is not None:
            raise ValidationError("指定的查阅会话已撤销")
        session_expires = from_storage(session["expires_at"])
        if session_expires is None or session_expires <= now_dt:
            raise ValidationError("指定的查阅会话已过期，不能授权")
        if expires > session_expires:
            raise ValidationError("临时解密不能晚于查阅会话本身的到期时间")
        granted_level = data["granted_level"]
        if LEVEL_RANK[granted_level] >= LEVEL_RANK[dossier["secrecy_level"]]:
            raise ValidationError("临时解密只能授予低于当前密级的查阅密级")
        existing = self.connection.execute(
            """SELECT id FROM temporary_declassifications
               WHERE dossier_id=? AND access_session_id=? AND revoked_at IS NULL AND expires_at>?""",
            (dossier_id, data["access_session_id"], to_storage(now_dt)),
        ).fetchone()
        if existing:
            raise ConflictError("该查阅会话已有生效中的临时解密授权")
        now_iso = to_storage(now_dt)
        code = f"SEC-TMP-{uuid.uuid4().hex[:12]}"
        cursor = self.connection.execute(
            """INSERT INTO temporary_declassifications(
                   grant_code,dossier_id,access_session_id,granted_by,granted_level,purpose,
                   granted_at,expires_at,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                code, dossier_id, data["access_session_id"], principal.user_id, granted_level,
                data["purpose"], now_iso, to_storage(expires), now_iso, now_iso,
            ),
        )
        grant = self.get_grant(cursor.lastrowid)
        self.dossiers.append_event(
            dossier_id, "secrecy.temp_declass_granted", principal.user_id, now_iso,
            details={
                "grant_id": grant["id"], "access_session_id": data["access_session_id"],
                "granted_level": granted_level, "expires_at": to_storage(expires),
            },
        )
        self.audit.record(
            principal, "secrecy.temp_declass.grant", "temporary_declassification", grant["id"], after=grant
        )
        return grant

    def get_grant(self, grant_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM temporary_declassifications WHERE id=?", (grant_id,)).fetchone()
        if row is None:
            raise NotFoundError("临时解密授权不存在")
        return dict(row)

    def revoke(self, principal: Principal, grant_id: int, reason: str) -> dict[str, Any]:
        principal.require("secrecy.temp_declass")
        before = self.get_grant(grant_id)
        if before["revoked_at"] is not None:
            raise ConflictError("临时解密授权已经撤销")
        now_iso = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE temporary_declassifications SET revoked_at=?,revoke_reason=?,revoked_by=?,updated_at=? WHERE id=?",
            (now_iso, reason, principal.user_id, now_iso, grant_id),
        )
        after = self.get_grant(grant_id)
        self.dossiers.append_event(
            before["dossier_id"], "secrecy.temp_declass_revoked", principal.user_id, now_iso,
            details={"grant_id": grant_id, "reason": reason},
        )
        self.audit.record(
            principal, "secrecy.temp_declass.revoke", "temporary_declassification", grant_id,
            before=before, after=after,
        )
        return after

    def effective_level(self, dossier_id: int, session_id: int) -> dict[str, Any]:
        """实时计算某查阅会话对某档案的有效密级；过期/会话失效一律不放行。"""
        now_dt = self.clock.now()
        now_iso = to_storage(now_dt)
        dossier = self.dossiers.get(dossier_id)
        row = self.connection.execute(
            """SELECT t.* FROM temporary_declassifications t
               JOIN sessions s ON s.id=t.access_session_id
               WHERE t.dossier_id=? AND t.access_session_id=? AND t.revoked_at IS NULL
                     AND t.expires_at>? AND s.revoked_at IS NULL AND s.expires_at>?
               ORDER BY t.id DESC LIMIT 1""",
            (dossier_id, session_id, now_iso, now_iso),
        ).fetchone()
        if row is None:
            return {
                "dossier_id": dossier_id, "secrecy_level": dossier["secrecy_level"],
                "effective_level": dossier["secrecy_level"], "temporarily_declassified": False,
                "grant": None, "checked_at": now_iso,
            }
        grant = dict(row)
        self.connection.execute(
            "UPDATE temporary_declassifications SET last_used_at=?,updated_at=? WHERE id=?",
            (now_iso, now_iso, grant["id"]),
        )
        return {
            "dossier_id": dossier_id, "secrecy_level": dossier["secrecy_level"],
            "effective_level": grant["granted_level"], "temporarily_declassified": True,
            "grant": {"id": grant["id"], "grant_code": grant["grant_code"], "expires_at": grant["expires_at"]},
            "checked_at": now_iso,
        }
