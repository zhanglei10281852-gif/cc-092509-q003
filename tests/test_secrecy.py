from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.database import get_connection
from app.core.clock import to_storage
from app.core.clock import FrozenClock
from app.archives.secrecy import SecrecyService, sweep_expired


def _iso(delta_hours: float) -> str:
    return to_storage(datetime.now(UTC) + timedelta(hours=delta_hours))


def _login(client, username, password):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"headers": {"Authorization": f"Bearer {body['token']}"}, "body": body}


def _make_user(client, admin, username, role_codes, password="Secrecy!23456"):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": password,
            "display_name": username,
            "role_codes": role_codes,
        },
    )
    assert created.status_code == 201, created.text
    return _login(client, username, password)


def _bootstrap_dossier(client, headers, *, code="SEC-001", project="P-SECRET", asset_type="工艺技术文档"):
    batch = client.post(
        "/api/dossiers/batches",
        headers=headers,
        json={"intake_code": f"BATCH-{code}", "project_code": project, "expected_count": 1},
    )
    assert batch.status_code == 201, batch.text
    dossier = client.post(
        "/api/dossiers",
        headers=headers,
        json={
            "dossier_code": code,
            "intake_id": batch.json()["id"],
            "asset_type": asset_type,
            "quantity": 1,
            "unit": "份",
        },
    )
    assert dossier.status_code == 201, dossier.text
    return dossier.json()


def test_policy_suggestion_considers_stage_asset_and_publication(client, admin):
    officer = _make_user(client, admin, "officer.sug", ["secrecy_officer"])

    def suggest(payload):
        response = client.post("/api/secrecy/policy/suggest", headers=officer["headers"], json=payload)
        assert response.status_code == 200, response.text
        return response.json()

    research = suggest(
        {"project_code": "P-X", "asset_type": "工艺技术文档", "lifecycle_stage": "research", "publication_state": "unpublished"}
    )
    production = suggest(
        {"project_code": "P-X", "asset_type": "工艺技术文档", "lifecycle_stage": "mass_production", "publication_state": "unpublished"}
    )
    published = suggest(
        {"project_code": "P-X", "asset_type": "工艺技术文档", "lifecycle_stage": "mass_production", "publication_state": "patent_published"}
    )
    assert research["suggested_level"] == "confidential"
    assert production["suggested_level"] == "top_secret"
    assert published["suggested_level"] == "internal"
    assert published["matched_scope"] == "builtin"

    # 项目进入量产后，缺省阶段也应按项目档案计算。
    client.put(
        "/api/secrecy/projects/profile",
        headers=officer["headers"],
        json={"project_code": "P-X", "lifecycle_stage": "mass_production"},
    )
    inferred = suggest({"project_code": "P-X", "asset_type": "工艺技术文档", "publication_state": "unpublished"})
    assert inferred["lifecycle_stage"] == "mass_production"
    assert inferred["suggested_level"] == "top_secret"


def test_upgrade_needs_two_distinct_reviewers_with_secrecy_office(client, admin):
    officer = _make_user(client, admin, "officer.up", ["secrecy_officer"])
    peer = _make_user(client, admin, "peer.up", ["approver"])
    manager = _make_user(client, admin, "manager.up", ["dossier_manager"])
    dossier = _bootstrap_dossier(client, manager["headers"])
    assert dossier["secrecy_level"] == "confidential"

    client.put(
        "/api/secrecy/projects/profile",
        headers=officer["headers"],
        json={"project_code": "P-SECRET", "lifecycle_stage": "mass_production"},
    )

    create = client.post(
        "/api/secrecy/adjustments",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "top_secret",
            "reason": "工艺已进入量产，涉密价值显著升高",
            "basis_code": "mass_production_escalation",
        },
    )
    assert create.status_code == 201, create.text
    request_id = create.json()["id"]
    assert create.json()["direction"] == "upgrade"
    assert create.json()["old_level"] == "confidential"

    # 普通档案管理员不能复核。
    forbidden = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=manager["headers"],
        json={"decision": "approve"},
    )
    assert forbidden.status_code == 403

    # 第一名复核人（非保密办公室）批准后仍需继续复核。
    first = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=peer["headers"],
        json={"decision": "approve", "comment": "情况属实"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "pending"
    assert any("保密办公室" in item for item in first.json()["pending_requirements"])

    # 同一复核人不能重复复核。
    duplicate = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=peer["headers"],
        json={"decision": "approve"},
    )
    assert duplicate.status_code == 409

    # 保密办公室复核后生效。
    second = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=officer["headers"],
        json={"decision": "approve", "comment": "同意升级"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["state"] == "applied"

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=manager["headers"]).json()
    assert detail["secrecy_level"] == "top_secret"


def test_requester_cannot_review_own_request(client, admin):
    officer = _make_user(client, admin, "officer.own", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.own", ["dossier_manager"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-OWN")
    create = client.post(
        "/api/secrecy/adjustments",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "restricted",
            "reason": "量产前工艺定型需要提升密级",
            "basis_code": "policy_revision",
        },
    )
    own = client.post(
        f"/api/secrecy/adjustments/{create.json()['id']}/reviews",
        headers=officer["headers"],
        json={"decision": "approve"},
    )
    assert own.status_code == 422


def test_review_rejected_request_does_not_change_level(client, admin):
    officer = _make_user(client, admin, "officer.rej", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.rej", ["dossier_manager"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-REJ")
    create = client.post(
        "/api/secrecy/adjustments",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "restricted",
            "reason": "依据不足的升级尝试",
            "basis_code": "incident_response",
        },
    )
    rejected = client.post(
        f"/api/secrecy/adjustments/{create.json()['id']}/reviews",
        headers=officer["headers"],
        json={"decision": "reject", "comment": "理由不成立"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["state"] == "rejected"
    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=manager["headers"]).json()
    assert detail["secrecy_level"] == "confidential"


def test_downgrade_only_after_publication_and_matches_policy(client, admin):
    officer = _make_user(client, admin, "officer.down", ["secrecy_officer"])
    peer = _make_user(client, admin, "peer.down", ["approver"])
    manager = _make_user(client, admin, "manager.down", ["dossier_manager"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-DOWN")

    before = client.post(
        "/api/secrecy/adjustments",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "internal",
            "reason": "准备随专利公开降级",
            "basis_code": "patent_publication",
        },
    )
    assert before.status_code == 409

    marked = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/patent-publication",
        headers=officer["headers"],
        json={"patent_published_at": "2026-09-01T00:00:00+00:00"},
    )
    assert marked.status_code == 200, marked.text
    assert marked.json()["suggestion"]["suggested_level"] == "internal"

    wrong_level = client.post(
        "/api/secrecy/adjustments",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "restricted",
            "reason": "尝试按非建议值调整",
            "basis_code": "periodic_review",
        },
    )
    # restricted 高于当前 confidential，属于升级，而公开后禁止升级。
    assert wrong_level.status_code == 409

    request = client.post(
        "/api/secrecy/adjustments",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "internal",
            "reason": "专利已公开，按制度降级",
            "basis_code": "patent_publication",
        },
    )
    assert request.status_code == 201, request.text
    assert request.json()["direction"] == "downgrade"
    request_id = request.json()["id"]

    # 降级必须由保密办公室复核，普通审批人不行。
    peer_review = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=peer["headers"],
        json={"decision": "approve"},
    )
    assert peer_review.status_code == 403

    office_review = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=officer["headers"],
        json={"decision": "approve", "comment": "公开日属实"},
    )
    assert office_review.status_code == 200
    assert office_review.json()["state"] == "applied"

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=manager["headers"]).json()
    assert detail["secrecy_level"] == "internal"
    assert detail["publication_state"] == "patent_published"


def test_review_after_deadline_expires_request(client, admin):
    officer = _make_user(client, admin, "officer.deadline", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.deadline", ["dossier_manager"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-DEAD")
    create = client.post(
        "/api/secrecy/adjustments",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "new_level": "restricted",
            "reason": "事件响应需要临时提升",
            "basis_code": "incident_response",
        },
    )
    request_id = create.json()["id"]

    # 直接把复核期限改到过去，模拟逾期后再复核。
    connection = get_connection()
    connection.execute(
        "UPDATE secrecy_adjustment_requests SET review_deadline=? WHERE id=?",
        ("2000-01-01T00:00:00+00:00", request_id),
    )
    connection.commit()

    late = client.post(
        f"/api/secrecy/adjustments/{request_id}/reviews",
        headers=officer["headers"],
        json={"decision": "approve"},
    )
    assert late.status_code == 409
    listed = client.get(
        "/api/secrecy/adjustments",
        headers=officer["headers"],
        params={"dossier_id": dossier["id"]},
    ).json()
    assert listed[0]["state"] == "expired"
    # 过期后档案密级保持旧值。
    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=officer["headers"]).json()
    assert detail["secrecy_level"] == "confidential"


def _open_loan(client, manager, dossier_id, user_id, due_at=None):
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=manager["headers"],
        json={
            "dossier_id": dossier_id,
            "requester_user_id": user_id,
            "quantity": 1,
            "due_at": due_at or _iso(120),
        },
    )
    assert loan.status_code == 201, loan.text
    return loan.json()


def test_temporary_declassification_is_session_scoped_and_expires(client, admin):
    officer = _make_user(client, admin, "officer.tmp", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.tmp", ["dossier_manager"])
    researcher = _make_user(client, admin, "reader.tmp", ["researcher"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-TMP")

    loan = _open_loan(client, manager, dossier["id"], researcher["body"]["user"]["id"], due_at=_iso(36))

    # 档案管理员不能授予临时解密。
    denied = client.post(
        "/api/secrecy/temporary-declassifications",
        headers=manager["headers"],
        json={
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "合作方现场核查需要查阅",
            "expires_at": _iso(24),
        },
    )
    assert denied.status_code == 403

    # 授权不能晚于查阅会话到期时间。
    overdue_grant = client.post(
        "/api/secrecy/temporary-declassifications",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "尝试覆盖到借阅到期之后",
            "expires_at": _iso(48),
        },
    )
    assert overdue_grant.status_code == 409

    granted = client.post(
        "/api/secrecy/temporary-declassifications",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "合作方现场核查需要查阅",
            "expires_at": _iso(24),
        },
    )
    assert granted.status_code == 201, granted.text
    grant_id = granted.json()["id"]

    # 重复授权被拒绝。
    duplicate = client.post(
        "/api/secrecy/temporary-declassifications",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "再次尝试授权",
            "expires_at": _iso(12),
        },
    )
    assert duplicate.status_code == 409

    effective = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/effective-level",
        headers=researcher["headers"],
        params={"access_loan_id": loan["id"]},
    ).json()
    assert effective["base_level"] == "confidential"
    assert effective["effective_level"] == "internal"
    assert effective["temporary_grant"]["access_loan_id"] == loan["id"]

    # 不带会话或别的会话都看不到解密后的密级。
    base = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/effective-level",
        headers=researcher["headers"],
    ).json()
    assert base["effective_level"] == "confidential"
    assert base["temporary_grant"] is None

    # 历史中应显示生效时间、操作者、依据以及仍在使用的会话。
    history = client.get(f"/api/secrecy/dossiers/{dossier['id']}/history", headers=officer["headers"]).json()
    assert history["active_sessions"][0]["access_loan_id"] == loan["id"]
    assert history["active_sessions"][0]["in_use"] is True
    kinds = {item["change_kind"] for item in history["history"]}
    assert {"initial", "temporary_decrypt"} <= kinds
    temp_record = next(item for item in history["history"] if item["change_kind"] == "temporary_decrypt")
    assert temp_record["actor_name"] == "officer.tmp"
    assert temp_record["effective_at"]
    assert temp_record["basis_code"] == "temporary_session_decrypt"

    # 撤销后立即恢复基础密级。
    revoked = client.post(
        f"/api/secrecy/temporary-declassifications/{grant_id}/revoke",
        headers=officer["headers"],
        json={"reason": "核查提前结束"},
    )
    assert revoked.status_code == 200
    after_revoke = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/effective-level",
        headers=researcher["headers"],
        params={"access_loan_id": loan["id"]},
    ).json()
    assert after_revoke["effective_level"] == "confidential"


def test_expired_grant_does_not_revive_after_restart(client, admin):
    officer = _make_user(client, admin, "officer.restart", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.restart", ["dossier_manager"])
    researcher = _make_user(client, admin, "reader.restart", ["researcher"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-RESTART")
    loan = _open_loan(client, manager, dossier["id"], researcher["body"]["user"]["id"])

    granted = client.post(
        "/api/secrecy/temporary-declassifications",
        headers=officer["headers"],
        json={
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "短暂解密",
            "expires_at": _iso(48),
        },
    )
    assert granted.status_code == 201

    # 将生效窗口改到过去，模拟重启后 sweep；过期授权不能重新生效。
    connection = get_connection()
    connection.execute(
        "UPDATE temporary_declassifications SET starts_at=?,expires_at=? WHERE id=?",
        ("1999-12-30T00:00:00+00:00", "2000-01-01T00:00:00+00:00", granted.json()["id"]),
    )
    connection.commit()

    from fastapi.testclient import TestClient

    from app.database import close_connection
    from app.main import app

    close_connection()
    with TestClient(app):
        effective = client.get(
            f"/api/secrecy/dossiers/{dossier['id']}/effective-level",
            headers=researcher["headers"],
            params={"access_loan_id": loan["id"]},
        ).json()
    assert effective["effective_level"] == "confidential"
    assert effective["temporary_grant"] is None

    history = client.get(f"/api/secrecy/dossiers/{dossier['id']}/history", headers=officer["headers"]).json()
    assert any(item["change_kind"] == "temp_decrypt_expired" for item in history["history"])
    assert history["active_sessions"] == []

    # sweep 幂等：再执行一次不会产生重复历史。
    close_connection()
    result = sweep_expired(get_connection())
    assert result["expired_grants"] == 0
    history2 = client.get(f"/api/secrecy/dossiers/{dossier['id']}/history", headers=officer["headers"]).json()
    expired_count = sum(1 for item in history2["history"] if item["change_kind"] == "temp_decrypt_expired")
    assert expired_count == 1


def test_sweep_service_with_frozen_clock(client, admin):
    from datetime import UTC, datetime, timedelta

    from app.core.security import Principal

    officer = _make_user(client, admin, "officer.frozen", ["secrecy_officer"])
    manager = _make_user(client, admin, "manager.frozen", ["dossier_manager"])
    researcher = _make_user(client, admin, "reader.frozen", ["researcher"])
    dossier = _bootstrap_dossier(client, manager["headers"], code="SEC-FROZEN")
    loan = _open_loan(client, manager, dossier["id"], researcher["body"]["user"]["id"])

    start = datetime(2026, 9, 26, tzinfo=UTC)
    officer_principal = Principal(
        user_id=officer["body"]["user"]["id"],
        username="officer.frozen",
        display_name="officer.frozen",
        department_id=None,
        permissions=frozenset({"secrecy.declassify", "dossiers.read"}),
        session_id=1,
    )
    reader_principal = Principal(
        user_id=researcher["body"]["user"]["id"],
        username="reader.frozen",
        display_name="reader.frozen",
        department_id=None,
        permissions=frozenset({"dossiers.read"}),
        session_id=2,
    )
    service = SecrecyService(get_connection(), FrozenClock(start))
    grant = service.grant_temporary_declassification(
        officer_principal,
        {
            "dossier_id": dossier["id"],
            "access_loan_id": loan["id"],
            "reason": "冻结时钟测试",
            "starts_at": None,
            "expires_at": to_storage(start + timedelta(hours=2)),
        },
    )

    # 生效窗口内。
    before = SecrecyService(get_connection(), FrozenClock(start + timedelta(hours=1)))
    response = before.effective_level(reader_principal, dossier["id"], loan["id"])
    assert response["effective_level"] == "internal"

    # 过期后由 sweep 自动失效。
    result = sweep_expired(get_connection(), FrozenClock(start + timedelta(hours=3)))
    assert result["expired_grants"] == 1
    after = SecrecyService(get_connection(), FrozenClock(start + timedelta(hours=3)))
    response = after.effective_level(reader_principal, dossier["id"], loan["id"])
    assert response["effective_level"] == "confidential"
    assert grant["grant_code"]


def test_reader_without_access_cannot_view_suggestions(client, admin):
    no_role = _make_user(client, admin, "nobody.secret", [])
    response = client.post(
        "/api/secrecy/policy/suggest",
        headers=no_role["headers"],
        json={"project_code": "P-X", "asset_type": "工艺技术文档"},
    )
    assert response.status_code == 403
