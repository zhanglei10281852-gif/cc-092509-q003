"""密级策略引擎。

密级建议完全由策略数据驱动：先查 secrecy_policy_rules 中
（项目、资产类型、研发/量产阶段、公开状态）四元组对应的规则；
没有显式规则时，使用与制度一致的兜底基线，保证任意资产都能得到建议。

专利公开后，制度要求按公开状态降级，因此 patent_published 维度的建议
恒为 internal，升级申请在专利公开状态下也不应被允许。
"""

from __future__ import annotations

import sqlite3
from typing import Any

from app.core.errors import ValidationError
from app.models import AssetKind, SecrecyLevel

# 数据库与接口统一使用枚举名（internal/...），枚举值（内部/...）仅用于展示。
LEVEL_RANK = {level.name: index for index, level in enumerate(SecrecyLevel)}
LEVELS = tuple(LEVEL_RANK)
STAGES = ("research", "mass_production")
PUBLICATION_STATES = ("unpublished", "patent_published")

# 制度兜底基线：未配置显式规则的资产类型按此矩阵建议密级。
FALLBACK_MATRIX: dict[tuple[str, str], str] = {
    ("research", "unpublished"): SecrecyLevel.confidential.name,
    ("mass_production", "unpublished"): SecrecyLevel.restricted.name,
    ("research", "patent_published"): SecrecyLevel.internal.name,
    ("mass_production", "patent_published"): SecrecyLevel.internal.name,
}

# 五类标准资产在研发/量产阶段的密级基线（公开状态统一按制度降级为内部）。
_UNPUBLISHED_BASELINE: dict[str, dict[str, str]] = {
    AssetKind.patent_disclosure.value: {
        "research": SecrecyLevel.confidential.name,
        "mass_production": SecrecyLevel.restricted.name,
    },
    AssetKind.technical_document.value: {
        "research": SecrecyLevel.confidential.name,
        "mass_production": SecrecyLevel.top_secret.name,
    },
    AssetKind.source_media.value: {
        "research": SecrecyLevel.confidential.name,
        "mass_production": SecrecyLevel.restricted.name,
    },
    AssetKind.laboratory_record.value: {
        "research": SecrecyLevel.internal.name,
        "mass_production": SecrecyLevel.confidential.name,
    },
    AssetKind.design_drawing.value: {
        "research": SecrecyLevel.confidential.name,
        "mass_production": SecrecyLevel.restricted.name,
    },
}


def canonical_rules() -> list[dict[str, str]]:
    """生成初始化用的内置策略规则（五型资产 × 两阶段 × 两公开状态）。"""
    rules: list[dict[str, str]] = []
    for asset_type, stages in _UNPUBLISHED_BASELINE.items():
        for stage in STAGES:
            rules.append(
                {
                    "project_code": "*",
                    "asset_type": asset_type,
                    "lifecycle_stage": stage,
                    "publication_state": "unpublished",
                    "suggested_level": stages[stage],
                    "rationale": _builtin_rationale(asset_type, stage, "unpublished", stages[stage]),
                }
            )
            rules.append(
                {
                    "project_code": "*",
                    "asset_type": asset_type,
                    "lifecycle_stage": stage,
                    "publication_state": "patent_published",
                    "suggested_level": SecrecyLevel.internal.name,
                    "rationale": "专利已公开，技术内容进入公知领域，按制度降为内部",
                }
            )
    return rules


def _builtin_rationale(asset_type: str, stage: str, publication_state: str, level: str) -> str:
    stage_label = "量产" if stage == "mass_production" else "研发试验"
    if level == SecrecyLevel.top_secret.name:
        return f"{asset_type}在量产后构成核心工艺秘密，{stage_label}阶段定为绝密"
    if level == SecrecyLevel.restricted.name:
        return f"{asset_type}进入量产后涉密范围与价值升高，{stage_label}阶段定为机密"
    if level == SecrecyLevel.confidential.name:
        return f"{asset_type}在{stage_label}阶段含有未公开技术信息，定为秘密"
    return f"{asset_type}在{stage_label}阶段按内部资料管理"


def normalize_level(value: str) -> str:
    if value not in LEVEL_RANK:
        raise ValidationError(f"未知密级：{value}")
    return value


def normalize_stage(value: str) -> str:
    if value not in STAGES:
        raise ValidationError("生命周期阶段只能是 research（研发试验）或 mass_production（量产）")
    return value


def normalize_publication_state(value: str) -> str:
    if value not in PUBLICATION_STATES:
        raise ValidationError("公开状态只能是 unpublished 或 patent_published")
    return value


class SecrecyPolicy:
    """根据项目、资产类型、阶段与公开状态计算建议密级。"""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def project_stage(self, project_code: str) -> str:
        row = self.connection.execute(
            "SELECT lifecycle_stage FROM secrecy_project_profiles WHERE project_code=?",
            (project_code,),
        ).fetchone()
        return row[0] if row else "research"

    def suggest(
        self,
        *,
        project_code: str,
        asset_type: str,
        publication_state: str,
        lifecycle_stage: str | None = None,
    ) -> dict[str, Any]:
        publication_state = normalize_publication_state(publication_state)
        stage = normalize_stage(lifecycle_stage or self.project_stage(project_code))
        row = self.connection.execute(
            """SELECT suggested_level,rationale,project_code,active
               FROM secrecy_policy_rules
               WHERE asset_type=? AND lifecycle_stage=? AND publication_state=?
                 AND project_code IN ('*', ?) AND active=1
               ORDER BY CASE project_code WHEN '*' THEN 1 ELSE 0 END
               LIMIT 1""",
            (asset_type, stage, publication_state, project_code),
        ).fetchone()
        if row and row["active"]:
            return {
                "suggested_level": row["suggested_level"],
                "rationale": row["rationale"],
                "matched_scope": "project" if row["project_code"] != "*" else "builtin",
                "project_code": project_code,
                "asset_type": asset_type,
                "lifecycle_stage": stage,
                "publication_state": publication_state,
            }
        if publication_state == "patent_published":
            level = SecrecyLevel.internal.name
            rationale = "专利已公开，技术内容进入公知领域，按制度降为内部"
        else:
            baseline = _UNPUBLISHED_BASELINE.get(asset_type)
            level = baseline[stage] if baseline else FALLBACK_MATRIX[(stage, "unpublished")]
            rationale = _builtin_rationale(asset_type, stage, publication_state, level)
        return {
            "suggested_level": level,
            "rationale": rationale,
            "matched_scope": "fallback",
            "project_code": project_code,
            "asset_type": asset_type,
            "lifecycle_stage": stage,
            "publication_state": publication_state,
        }
