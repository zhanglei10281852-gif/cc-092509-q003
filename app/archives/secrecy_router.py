from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.archives.secrecy import SecrecyService, sweep_expired
from app.archives.secrecy_schemas import (
    AdjustmentCreate,
    AdjustmentReview,
    LevelSuggestionQuery,
    PatentPublicationMark,
    PolicyRuleUpsert,
    ProjectProfileUpsert,
    TemporaryDeclassificationGrant,
    TemporaryDeclassificationRevoke,
)

router = APIRouter(prefix="/api/secrecy", tags=["密级管理"])


@router.put("/projects/profile")
def upsert_project_profile(payload: ProjectProfileUpsert, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).upsert_profile(principal, payload.model_dump())


@router.get("/projects/profile")
def list_project_profiles(principal: Principal = Depends(current_principal)):
    return SecrecyService(get_connection()).list_profiles(principal)


@router.put("/policy/rules")
def upsert_policy_rule(payload: PolicyRuleUpsert, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).upsert_rule(principal, payload.model_dump())


@router.get("/policy/rules")
def list_policy_rules(
    project_code: str | None = Query(default=None),
    asset_type: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return SecrecyService(get_connection()).list_rules(principal, project_code, asset_type)


@router.post("/policy/suggest")
def suggest_level(payload: LevelSuggestionQuery, principal: Principal = Depends(current_principal)):
    return SecrecyService(get_connection()).suggest(principal, payload.model_dump())


@router.post("/dossiers/{dossier_id}/patent-publication")
def mark_patent_published(dossier_id: int, payload: PatentPublicationMark, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).mark_patent_published(principal, dossier_id, payload.model_dump())


@router.post("/adjustments", status_code=status.HTTP_201_CREATED)
def create_adjustment(payload: AdjustmentCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).create_adjustment(principal, payload.model_dump())


@router.get("/adjustments")
def list_adjustments(
    state: str | None = Query(default=None),
    dossier_id: int | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    # 查询前先把超期申请落库为 expired，避免列表展示陈旧的 pending。
    with transaction(immediate=True) as connection:
        sweep_expired(connection)
    return SecrecyService(get_connection()).list_adjustments(principal, state, dossier_id)


@router.post("/adjustments/{request_id}/reviews")
def review_adjustment(request_id: int, payload: AdjustmentReview, principal: Principal = Depends(current_principal)):
    # 先在独立事务中清理超期申请，避免复核失败回滚把逾期标记一起撤销。
    with transaction(immediate=True) as connection:
        swept = sweep_expired(connection)
    with transaction(immediate=True) as connection:
        result = SecrecyService(connection).review_adjustment(principal, request_id, payload.model_dump())
    if swept.get("expired_requests") or swept.get("expired_grants"):
        result["swept_before_review"] = swept
    return result


@router.post("/temporary-declassifications", status_code=status.HTTP_201_CREATED)
def grant_temporary_declassification(payload: TemporaryDeclassificationGrant, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).grant_temporary_declassification(principal, payload.model_dump())


@router.get("/temporary-declassifications")
def list_temporary_declassifications(
    active_only: bool = Query(default=False),
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        sweep_expired(connection)
    return SecrecyService(get_connection()).list_grants(principal, active_only)


@router.post("/temporary-declassifications/{grant_id}/revoke")
def revoke_temporary_declassification(
    grant_id: int,
    payload: TemporaryDeclassificationRevoke,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        return SecrecyService(connection).revoke_temporary_declassification(principal, grant_id, payload.reason)


@router.get("/dossiers/{dossier_id}/effective-level")
def effective_level(
    dossier_id: int,
    access_loan_id: int | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return SecrecyService(get_connection()).effective_level(principal, dossier_id, access_loan_id)


@router.get("/dossiers/{dossier_id}/history")
def level_history(dossier_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        sweep_expired(connection)
    return SecrecyService(get_connection()).history(principal, dossier_id)
