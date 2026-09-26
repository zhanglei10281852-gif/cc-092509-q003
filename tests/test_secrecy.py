from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.archives.secrecy import (
    SecrecyAdjustmentService,
    TemporaryDeclassificationService,
)
from app.core.clock import FrozenClock
from app.core.security import Principal
from app.database import transaction


def _login(client, username, password):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    headers = {"Authorization": f"Bearer {body['token']}"}
    me = client.get("/api/auth/me", headers=headers)
    return {
        "headers": headers,
        "user_id": me.json()["user_id"],
        "session_id": me.json()["session_id"],
        "permissions": set(me.json()["permissions"]),
    }


def _make_user(client, admin, username, role_codes):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Reviewer!23456",
            "display_name": f"用户{username}",
            "role_codes": role_codes,
        },
    )
    assert created.status_code == 201, created.text
    return _login(client, username, "Reviewer!23456")


def _bootstrap_dossier(client, admin, project_code="P-ALPHA", asset_type="工艺技术文档"):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": f"V-{project_code}",
            "building": "科研楼",
            "room": "保密间",
            "cabinet": "柜一",
            "shelf": "一层",
            "sensitivity": "restricted",
            "capacity_units": 100,
        },
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"B-{project_code}", "project_code": project_code, "expected_count": 1},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": f"D-{project_code}",
            "intake_id": batch["id"],
            "asset_type": asset_type,
            "quantity": 1,
            "unit": "份",
            "vault_id": vault["id"],
            # 即使调用方伪造密级，登记结果也必须来自制度策略
            "secrecy_level": "internal",
        },
    ).json()
    return dossier


def test_suggested_level_follows_project_type_and_stage(client, admin):
    suggest = client.get(
        "/api/secrecy/suggestions",
        headers=admin["headers"],
        params={"project_code": "P-ALPHA", "asset_type": "工艺技术文档", "stage": "research"},
    )
    assert suggest.status_code == 200
    assert suggest.json()["suggested_level"] == "restricted"

    production = client.get(
        "/api/secrecy/suggestions",
        headers=admin["headers"],
        params={"project_code": "P-ALPHA", "asset_type": "工艺技术文档", "stage": "production"},
    )
    assert production.json()["suggested_level"] == "top_secret"

    published = client.get(
        "/api/secrecy/suggestions",
        headers=admin["headers"],
        params={"project_code": "P-ALPHA", "asset_type": "工艺技术文档", "stage": "patent_published"},
    )
    assert published.json()["suggested_level"] == "internal"

    # 具体项目策略优先于通配策略
    created = client.post(
        "/api/secrecy/policies",
        headers=admin["headers"],
        json={
            "policy_code": "SEC-P-ALPHA-RD",
            "project_code": "P-ALPHA",
            "asset_type": "*",
            "stage": "research",
            "suggested_level": "confidential",
            "basis": "P-ALPHA 项目研发期按秘密管理的专项约定",
            "priority": 50,
        },
    )
    assert created.status_code == 201, created.text
    again = client.get(
        "/api/secrecy/suggestions",
        headers=admin["headers"],
        params={"project_code": "P-ALPHA", "asset_type": "工艺技术文档", "stage": "research"},
    )
    assert again.json()["suggested_level"] == "confidential"
    other = client.get(
        "/api/secrecy/suggestions",
        headers=admin["headers"],
        params={"project_code": "P-OTHER", "asset_type": "工艺技术文档", "stage": "research"},
    )
    assert other.json()["suggested_level"] == "restricted"


def test_dossier_registered_at_policy_level_and_copies_inherit(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    assert dossier["secrecy_level"] == "restricted"
    issue = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={
            "requested_quantity": 1,
            "loss_quantity": 0,
            "children": [{"dossier_code": "D-P-ALPHA-COPY", "quantity": 1}],
        },
    )
    assert issue.status_code == 201, issue.text
    assert issue.json()["children"][0]["secrecy_level"] == "restricted"


def test_upgrade_requires_two_distinct_authorized_reviewers(client, admin):
    manager = _make_user(client, admin, "manager1", ["dossier_manager"])
    approver_one = _make_user(client, admin, "approver.a", ["approver"])
    approver_two = _make_user(client, admin, "approver.b", ["approver"])

    dossier = _bootstrap_dossier(client, admin)
    started_at = (datetime.now(UTC) - timedelta(days=1)).isoformat(timespec="seconds")
    marked = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/stage",
        headers=manager["headers"],
        json={"production_started_at": started_at, "note": "产线 SOP 冻结，进入量产"},
    )
    assert marked.status_code == 200, marked.text
    suggestion = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/suggestion", headers=manager["headers"]
    ).json()
    assert suggestion["stage"] == "production"
    assert suggestion["suggested_level"] == "top_secret"

    requested = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/adjustments",
        headers=manager["headers"],
        json={"reason": "量产后工艺价值升高，保密办公室要求升级"},
    )
    assert requested.status_code == 201, requested.text
    adjustment_id = requested.json()["id"]
    assert requested.json()["direction"] == "upgrade"
    assert requested.json()["required_reviews"] == 2
    assert requested.json()["from_level"] == "restricted"
    assert requested.json()["to_level"] == "top_secret"

    # 普通管理员（发起人）没有复核权限，不能自行通过
    own = client.post(
        f"/api/secrecy/adjustments/{adjustment_id}/decisions",
        headers=manager["headers"],
        json={"decision": "approve"},
    )
    assert own.status_code == 403

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert detail["secrecy_level"] == "restricted"

    first = client.post(
        f"/api/secrecy/adjustments/{adjustment_id}/decisions",
        headers=approver_one["headers"],
        json={"decision": "approve", "comment": "同意升级"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "pending"

    # 同一复核人不能重复签署
    duplicate = client.post(
        f"/api/secrecy/adjustments/{adjustment_id}/decisions",
        headers=approver_one["headers"],
        json={"decision": "approve"},
    )
    assert duplicate.status_code == 409

    second = client.post(
        f"/api/secrecy/adjustments/{adjustment_id}/decisions",
        headers=approver_two["headers"],
        json={"decision": "approve", "comment": "复核无误"},
    )
    assert second.status_code == 200, second.text
    approved = second.json()
    assert approved["state"] == "approved"
    assert approved["effective_at"] is not None
    assert len(approved["reviews"]) == 2

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert detail["secrecy_level"] == "top_secret"


def test_downgrade_needs_one_review_and_must_match_suggestion(client, admin):
    manager = _make_user(client, admin, "manager2", ["dossier_manager"])
    approver_one = _make_user(client, admin, "approver.c", ["approver"])

    dossier = _bootstrap_dossier(client, admin)

    # 研发期建议密级仍为 restricted，不得无依据降级
    forbidden = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/adjustments",
        headers=manager["headers"],
        json={"to_level": "internal", "reason": "合作方需要查阅"},
    )
    assert forbidden.status_code == 422
    assert forbidden.json()["error"]["context"]["suggested_level"] == "restricted"

    published_at = (datetime.now(UTC) - timedelta(days=1)).isoformat(timespec="seconds")
    client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/stage",
        headers=manager["headers"],
        json={"patent_published_at": published_at, "note": "专利公开日已到"},
    )

    requested = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/adjustments",
        headers=manager["headers"],
        json={"reason": "专利已公开，按制度降级为内部"},
    )
    assert requested.status_code == 201, requested.text
    adjustment_id = requested.json()["id"]
    assert requested.json()["direction"] == "downgrade"
    assert requested.json()["required_reviews"] == 1

    decided = client.post(
        f"/api/secrecy/adjustments/{adjustment_id}/decisions",
        headers=approver_one["headers"],
        json={"decision": "approve", "comment": "公开日属实"},
    )
    assert decided.status_code == 200
    assert decided.json()["state"] == "approved"

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert detail["secrecy_level"] == "internal"


def test_adjustment_expires_after_deadline_and_never_takes_effect(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    approver_one = _make_user(client, admin, "approver.d", ["approver"])

    start = datetime(2026, 9, 26, 8, 0, tzinfo=UTC)
    clock = FrozenClock(start)
    with transaction(immediate=True) as connection:
        service = SecrecyAdjustmentService(connection, clock)
        admin_principal = Principal(
            1, "admin", "档案平台主管", None, frozenset({"*"}), session_id=1
        )
        requested = service.request_adjustment(
            admin_principal,
            dossier["id"],
            {
                "to_level": "top_secret",
                "reason": "量产临近，提前申请升级",
                "review_deadline": (start + timedelta(hours=48)).isoformat(),
            },
        )
        adjustment_id = requested["id"]

        # 普通复核人在期限内只凑到一票（升级需两票）
        approver_principal = Principal(
            approver_one["user_id"],
            "approver.d",
            "用户approver.d",
            None,
            frozenset(approver_one["permissions"]),
            session_id=9001,
        )
        first = service.decide(approver_principal, adjustment_id, {"decision": "approve", "comment": "同意"})
        assert first["state"] == "pending"

        # 复核期限过后，第二票不能再让调整生效
        clock.advance(hours=49)
        try:
            service.decide(approver_principal, adjustment_id, {"decision": "approve", "comment": "逾期补签"})
            raise AssertionError("逾期复核必须被拒绝")
        except Exception as exc:  # noqa: BLE001
            assert "已经结束" in str(exc)

        expired = service.get_adjustment(adjustment_id)
        assert expired["state"] == "expired"
        assert expired["effective_at"] is None

    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert detail["secrecy_level"] == "restricted"


def test_temporary_declassification_scoped_to_session_and_expires(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    manager = _make_user(client, admin, "manager3", ["dossier_manager"])
    viewer = _make_user(client, admin, "viewer1", ["approver"])
    other_viewer = _make_user(client, admin, "viewer2", ["approver"])

    start = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
    grant_id: int
    with transaction(immediate=True) as connection:
        # 让目标查阅会话覆盖冻结时钟的时间窗
        connection.execute(
            "UPDATE sessions SET expires_at=? WHERE id=?",
            ((start + timedelta(hours=10)).isoformat(), viewer["session_id"]),
        )
        clock = FrozenClock(start)
        service = TemporaryDeclassificationService(connection, clock)
        manager_principal = Principal(
            manager["user_id"], "manager3", "用户manager3", None,
            frozenset(manager["permissions"]), session_id=manager["session_id"],
        )
        grant = service.grant(
            manager_principal,
            dossier["id"],
            {
                "access_session_id": viewer["session_id"],
                "purpose": "专利代理机构现场查阅交底书",
                "expires_at": (start + timedelta(hours=2)).isoformat(),
                "granted_level": "internal",
            },
        )
        grant_id = grant["id"]

        viewer_principal = Principal(
            viewer["user_id"], "viewer1", "用户viewer1", None,
            frozenset(viewer["permissions"]), session_id=viewer["session_id"],
        )
        other_principal = Principal(
            other_viewer["user_id"], "viewer2", "用户viewer2", None,
            frozenset(other_viewer["permissions"]), session_id=other_viewer["session_id"],
        )

        effective = service.effective_level(dossier["id"], viewer["session_id"])
        assert effective["temporarily_declassified"] is True
        assert effective["effective_level"] == "internal"
        assert effective["secrecy_level"] == "restricted"

        # 临时解密只对指定查阅会话生效
        unscoped = service.effective_level(dossier["id"], other_viewer["session_id"])
        assert unscoped["temporarily_declassified"] is False
        assert unscoped["effective_level"] == "restricted"
        del viewer_principal, other_principal

        # 到期后自动失效
        clock.advance(hours=3)
        expired_view = service.effective_level(dossier["id"], viewer["session_id"])
        assert expired_view["temporarily_declassified"] is False
        assert expired_view["effective_level"] == "restricted"

    # 模拟服务重启：全新实例、无任何内存状态，过期授权依旧不能复活
    with transaction(immediate=True) as connection:
        restarted = TemporaryDeclassificationService(connection, FrozenClock(start + timedelta(hours=3)))
        after_restart = restarted.effective_level(dossier["id"], viewer["session_id"])
        assert after_restart["temporarily_declassified"] is False

    # 历史查询显示依据、操作者、生效时间和仍在使用的会话
    history = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/history", headers=admin["headers"]
    ).json()
    assert history["current_level"] == "restricted"
    grants = history["temporary_declassifications"]
    assert len(grants) == 1
    assert grants[0]["id"] == grant_id
    assert grants[0]["status"] == "expired"
    assert grants[0]["access_session_id"] == viewer["session_id"]
    assert grants[0]["granted_by_name"] == "用户manager3"
    assert grants[0]["last_used_at"] is not None
    assert history["active_temporary_declassifications"] == []


def test_temporary_declassification_rejects_revoked_or_overlong_session(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    manager = _make_user(client, admin, "manager4", ["dossier_manager"])
    viewer = _make_user(client, admin, "viewer3", ["approver"])

    # 登出即撤销会话，不能授权
    client.post("/api/auth/logout", headers=viewer["headers"])
    response = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/temporary-declassifications",
        headers=manager["headers"],
        json={
            "access_session_id": viewer["session_id"],
            "purpose": "试图对已退出会话授权",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert response.status_code == 422

    fresh = _make_user(client, admin, "viewer4", ["approver"])
    too_long = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/temporary-declassifications",
        headers=manager["headers"],
        json={
            "access_session_id": fresh["session_id"],
            "purpose": "超过七天的长期解密",
            "expires_at": (datetime.now(UTC) + timedelta(days=8)).isoformat(),
        },
    )
    assert too_long.status_code == 422


def test_history_records_effective_time_operator_basis_and_active_session(client, admin):
    manager = _make_user(client, admin, "manager5", ["dossier_manager"])
    approver_one = _make_user(client, admin, "approver.e", ["approver"])
    viewer = _make_user(client, admin, "viewer5", ["approver"])
    dossier = _bootstrap_dossier(client, admin, project_code="P-BETA")

    client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/stage",
        headers=manager["headers"],
        json={"production_started_at": (datetime.now(UTC) - timedelta(days=2)).isoformat()},
    )
    requested = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/adjustments",
        headers=manager["headers"],
        json={"reason": "量产升级"},
    )
    # 升级需要两名复核人：用 admin（非申请人，持全部权限）和 approver 各一票
    client.post(
        f"/api/secrecy/adjustments/{requested.json()['id']}/decisions",
        headers=admin["headers"],
        json={"decision": "approve", "comment": "保密办公室主任同意"},
    )
    decided = client.post(
        f"/api/secrecy/adjustments/{requested.json()['id']}/decisions",
        headers=approver_one["headers"],
        json={"decision": "approve", "comment": "风险审批人同意"},
    )
    assert decided.json()["state"] == "approved"

    # 升级到绝密后，给指定会话签发 2 小时临时解密
    grant = client.post(
        f"/api/secrecy/dossiers/{dossier['id']}/temporary-declassifications",
        headers=manager["headers"],
        json={
            "access_session_id": viewer["session_id"],
            "purpose": "尽调现场查阅",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            "granted_level": "confidential",
        },
    )
    assert grant.status_code == 201, grant.text

    # 指定会话实际使用一次
    used = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/effective-level", headers=viewer["headers"]
    )
    assert used.json()["temporarily_declassified"] is True

    history = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/history", headers=admin["headers"]
    ).json()
    assert history["current_level"] == "top_secret"
    adjustment = history["adjustments"][0]
    assert adjustment["from_level"] == "restricted"
    assert adjustment["to_level"] == "top_secret"
    assert adjustment["effective_at"] is not None
    assert adjustment["basis"]  # 依据制度条款
    assert adjustment["requested_by_name"] == "用户manager5"
    reviewer_names = {item["reviewer_name"] for item in adjustment["reviews"]}
    assert "用户approver.e" in reviewer_names
    assert "系统管理员" in reviewer_names

    active = history["active_temporary_declassifications"]
    assert len(active) == 1
    assert active[0]["access_session_id"] == viewer["session_id"]
    assert active[0]["session_username"] == "viewer5"
    assert active[0]["status"] == "active"
    assert active[0]["last_used_at"] is not None

    # 提前收回后，该会话不再出现在仍在使用列表中
    revoked = client.post(
        f"/api/secrecy/temporary-declassifications/{active[0]['id']}/revoke",
        headers=manager["headers"],
        json={"reason": "查阅提前结束"},
    )
    assert revoked.status_code == 200
    after = client.get(
        f"/api/secrecy/dossiers/{dossier['id']}/history", headers=admin["headers"]
    ).json()
    assert after["active_temporary_declassifications"] == []
    assert after["temporary_declassifications"][0]["status"] == "revoked"
