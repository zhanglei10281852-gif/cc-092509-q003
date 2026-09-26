from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

SecrecyLevelLiteral = Literal["internal", "confidential", "restricted", "top_secret"]
StageLiteral = Literal["research", "production", "patent_published", "any"]


class SecrecyPolicyCreate(BaseModel):
    policy_code: str = Field(min_length=3, max_length=64)
    project_code: str = Field(min_length=1, max_length=64, description="项目编码，* 表示通配")
    asset_type: str = Field(min_length=1, max_length=100, description="资产类型，* 表示通配")
    stage: StageLiteral
    suggested_level: SecrecyLevelLiteral
    basis: str = Field(min_length=4, max_length=500)
    priority: int = Field(default=100, ge=1, le=10_000)


class StageMarkerUpdate(BaseModel):
    production_started_at: str | None = Field(default=None, min_length=10, max_length=40)
    patent_published_at: str | None = Field(default=None, min_length=10, max_length=40)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def at_least_one(self):
        if self.production_started_at is None and self.patent_published_at is None:
            raise ValueError("至少提供量产时间或专利公开日之一")
        return self


class AdjustmentCreate(BaseModel):
    to_level: SecrecyLevelLiteral | None = Field(
        default=None, description="目标密级；缺省时采用制度建议密级"
    )
    reason: str = Field(min_length=4, max_length=1000)
    review_deadline: str | None = Field(default=None, min_length=10, max_length=40)


class AdjustmentDecision(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class TemporaryDeclassificationCreate(BaseModel):
    access_session_id: int = Field(gt=0)
    purpose: str = Field(min_length=4, max_length=500)
    expires_at: str = Field(min_length=10, max_length=40)
    granted_level: SecrecyLevelLiteral = Field(
        default="internal", description="临时降低后的查阅密级，必须低于当前密级"
    )


class TemporaryDeclassificationRevoke(BaseModel):
    reason: str = Field(default="保密办公室提前收回", min_length=2, max_length=200)
