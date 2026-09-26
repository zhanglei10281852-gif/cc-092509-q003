from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Level = Literal["internal", "confidential", "restricted", "top_secret"]


class ProjectProfileUpsert(BaseModel):
    project_code: str = Field(min_length=2, max_length=64)
    lifecycle_stage: Literal["research", "mass_production"]
    secrecy_office_owner_id: int | None = Field(default=None, gt=0)
    note: str = Field(default="", max_length=500)


class PolicyRuleUpsert(BaseModel):
    project_code: str = Field(min_length=1, max_length=64, description="使用 * 表示内置基线")
    asset_type: str = Field(min_length=1, max_length=100)
    lifecycle_stage: Literal["research", "mass_production"]
    publication_state: Literal["unpublished", "patent_published"]
    suggested_level: Level
    rationale: str = Field(min_length=2, max_length=500)


class LevelSuggestionQuery(BaseModel):
    project_code: str = Field(min_length=2, max_length=64)
    asset_type: str = Field(min_length=1, max_length=100)
    lifecycle_stage: Literal["research", "mass_production"] | None = None
    publication_state: Literal["unpublished", "patent_published"] = "unpublished"


class AdjustmentCreate(BaseModel):
    dossier_id: int = Field(gt=0)
    new_level: Level
    reason: str = Field(min_length=4, max_length=500)
    basis_code: Literal[
        "mass_production_escalation",
        "policy_revision",
        "incident_response",
        "patent_publication",
        "periodic_review",
    ]
    basis_detail: str = Field(default="", max_length=500)
    review_deadline: str | None = Field(default=None, description="ISO-8601；不传时按制度默认期限")


class AdjustmentReview(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class PatentPublicationMark(BaseModel):
    patent_published_at: str = Field(min_length=10, max_length=40)
    note: str = Field(default="", max_length=500)


class TemporaryDeclassificationGrant(BaseModel):
    dossier_id: int = Field(gt=0)
    access_loan_id: int = Field(gt=0)
    reason: str = Field(min_length=4, max_length=500)
    starts_at: str | None = Field(default=None, description="ISO-8601；不传表示立即生效")
    expires_at: str = Field(min_length=10, max_length=40)
    expected_base_level: Level | None = None

    @model_validator(mode="after")
    def _check_window(self):
        if self.starts_at and self.expires_at <= self.starts_at:
            raise ValueError("expires_at 必须晚于 starts_at")
        return self


class TemporaryDeclassificationRevoke(BaseModel):
    reason: str = Field(min_length=2, max_length=500)
