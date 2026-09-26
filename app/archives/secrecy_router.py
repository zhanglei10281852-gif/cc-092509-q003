from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.archives.secrecy import (
    SecrecyAdjustmentService,
    SecrecyPolicyService,
    TemporaryDeclassificationService,
)
from app.archives.secrecy_schemas import (
    AdjustmentCreate,
    AdjustmentDecision,
    SecrecyPolicyCreate,
    StageMarkerUpdate,
    TemporaryDeclassificationCreate,
    TemporaryDeclassificationRevoke,
)
from app.core.security import Principal
from app.database import get_connection, transaction

router = APIRouter(prefix="/api/secrecy", tags=["密级管理"])


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def create_policy(payload: SecrecyPolicyCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyPolicyService(connection).create_policy(principal, payload.model_dump())


@router.get("/policies")
def list_policies(
    active_only: bool = Query(default=True),
    principal: Principal = Depends(current_principal),
):
    return SecrecyPolicyService(get_connection()).list_policies(principal, active_only)


@router.get("/suggestions")
def suggest_level(
    project_code: str = Query(min_length=1, max_length=64),
    asset_type: str = Query(min_length=1, max_length=100),
    stage: str = Query(min_length=1, max_length=20),
    principal: Principal = Depends(current_principal),
):
    return SecrecyPolicyService(get_connection()).suggest(principal, project_code, asset_type, stage)


@router.get("/dossiers/{dossier_id}/suggestion")
def dossier_suggestion(dossier_id: int, principal: Principal = Depends(current_principal)):
    return SecrecyAdjustmentService(get_connection()).suggestion_for_dossier(principal, dossier_id)


@router.post("/dossiers/{dossier_id}/stage")
def mark_stage(dossier_id: int, payload: StageMarkerUpdate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyAdjustmentService(connection).mark_stage(principal, dossier_id, payload.model_dump())


@router.post("/dossiers/{dossier_id}/adjustments", status_code=status.HTTP_201_CREATED)
def request_adjustment(dossier_id: int, payload: AdjustmentCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyAdjustmentService(connection).request_adjustment(principal, dossier_id, payload.model_dump())


@router.post("/adjustments/{adjustment_id}/decisions")
def decide_adjustment(adjustment_id: int, payload: AdjustmentDecision, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyAdjustmentService(connection).decide(principal, adjustment_id, payload.model_dump())


@router.get("/adjustments/{adjustment_id}")
def get_adjustment(adjustment_id: int, principal: Principal = Depends(current_principal)):
    principal.require("secrecy.read")
    return SecrecyAdjustmentService(get_connection()).get_adjustment(adjustment_id)


@router.post("/adjustments/sweep-expired")
def sweep_expired(principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyAdjustmentService(connection).sweep_expired(principal)


@router.get("/dossiers/{dossier_id}/history")
def adjustment_history(dossier_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return SecrecyAdjustmentService(connection).history(principal, dossier_id)


@router.post("/dossiers/{dossier_id}/temporary-declassifications", status_code=status.HTTP_201_CREATED)
def grant_temp_declassification(
    dossier_id: int,
    payload: TemporaryDeclassificationCreate,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        return TemporaryDeclassificationService(connection).grant(principal, dossier_id, payload.model_dump())


@router.post("/temporary-declassifications/{grant_id}/revoke")
def revoke_temp_declassification(
    grant_id: int,
    payload: TemporaryDeclassificationRevoke,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        return TemporaryDeclassificationService(connection).revoke(principal, grant_id, payload.reason)


@router.get("/dossiers/{dossier_id}/effective-level")
def effective_level(
    dossier_id: int,
    principal: Principal = Depends(current_principal),
):
    principal.require("secrecy.read")
    return TemporaryDeclassificationService(get_connection()).effective_level(
        dossier_id, principal.session_id
    )
