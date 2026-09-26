from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.core.clock import to_storage, utc_now

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "archives.db"
_local = threading.local()

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    manager TEXT NOT NULL,
    phone TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    department_id INTEGER REFERENCES departments(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','locked')),
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    password_changed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TEXT NOT NULL,
    PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by INTEGER REFERENCES users(id),
    assigned_at TEXT NOT NULL,
    PRIMARY KEY(user_id, role_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    revoke_reason TEXT,
    client_label TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id),
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('success','denied','failure')),
    before_json TEXT,
    after_json TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    correlation_id TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);

CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS background_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL,
    deduplication_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TEXT NOT NULL,
    locked_at TEXT,
    locked_by TEXT,
    result_json TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_ready ON background_jobs(status, available_at);

CREATE TABLE IF NOT EXISTS vault_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    building TEXT NOT NULL,
    room TEXT NOT NULL,
    cabinet TEXT NOT NULL,
    shelf TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK(sensitivity IN ('normal','restricted','critical')),
    capacity_units INTEGER NOT NULL CHECK(capacity_units > 0),
    version INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disclosure_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    disclosure_code TEXT NOT NULL UNIQUE,
    project_code TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    quantity REAL NOT NULL CHECK(quantity > 0),
    unit TEXT NOT NULL,
    preservation TEXT NOT NULL,
    chain_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intake_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    intake_code TEXT NOT NULL UNIQUE,
    project_code TEXT NOT NULL,
    received_by INTEGER NOT NULL REFERENCES users(id),
    received_at TEXT NOT NULL,
    expected_count INTEGER NOT NULL CHECK(expected_count > 0),
    accepted_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK(status IN ('open','reconciled','quarantined','closed')),
    qr_payload TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dossiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dossier_code TEXT NOT NULL UNIQUE,
    intake_id INTEGER NOT NULL REFERENCES intake_batches(id),
    disclosure_event_id INTEGER REFERENCES disclosure_events(id),
    source_dossier_id INTEGER REFERENCES dossiers(id),
    root_dossier_id INTEGER REFERENCES dossiers(id),
    asset_type TEXT NOT NULL,
    quantity REAL NOT NULL CHECK(quantity >= 0),
    reserved_quantity REAL NOT NULL DEFAULT 0 CHECK(reserved_quantity >= 0),
    unit TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN ('received','available','access_loaned','partially_disclosed','disclosed','quarantined','pending_disposal','disposed')),
    vault_id INTEGER REFERENCES vault_locations(id),
    custody_user_id INTEGER REFERENCES users(id),
    secrecy_level TEXT NOT NULL DEFAULT 'internal'
        CHECK(secrecy_level IN ('internal','confidential','restricted','top_secret')),
    production_started_at TEXT,
    patent_published_at TEXT,
    provenance_depth INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(reserved_quantity <= quantity)
);
CREATE INDEX IF NOT EXISTS idx_dossiers_batch ON dossiers(intake_id);
CREATE INDEX IF NOT EXISTS idx_dossiers_parent ON dossiers(source_dossier_id);
CREATE INDEX IF NOT EXISTS idx_dossiers_vault ON dossiers(vault_id);

CREATE TABLE IF NOT EXISTS copy_issue_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_code TEXT NOT NULL UNIQUE,
    source_dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    requested_quantity REAL NOT NULL CHECK(requested_quantity > 0),
    produced_quantity REAL NOT NULL CHECK(produced_quantity >= 0),
    loss_quantity REAL NOT NULL CHECK(loss_quantity >= 0),
    operator_user_id INTEGER NOT NULL REFERENCES users(id),
    occurred_at TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_code TEXT NOT NULL UNIQUE,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    requester_user_id INTEGER NOT NULL REFERENCES users(id),
    approved_request_id INTEGER REFERENCES approval_requests(id),
    quantity REAL NOT NULL CHECK(quantity > 0),
    due_at TEXT NOT NULL,
    returned_quantity REAL NOT NULL DEFAULT 0 CHECK(returned_quantity >= 0),
    state TEXT NOT NULL CHECK(state IN ('active','partially_returned','returned','overdue','disputed')),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(returned_quantity <= quantity)
);

CREATE TABLE IF NOT EXISTS disclosure_use_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    recipient_code TEXT NOT NULL,
    quantity REAL NOT NULL CHECK(quantity > 0),
    operator_user_id INTEGER NOT NULL REFERENCES users(id),
    idempotency_key TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(dossier_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_code TEXT NOT NULL UNIQUE,
    action_type TEXT NOT NULL CHECK(action_type IN ('access_loan','disposal','vault_reveal','inventory_review_adjustment')),
    resource_type TEXT NOT NULL,
    resource_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL REFERENCES users(id),
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','cancelled','expired','executed')),
    required_approvals INTEGER NOT NULL DEFAULT 2 CHECK(required_approvals >= 2),
    expires_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    approver_user_id INTEGER NOT NULL REFERENCES users(id),
    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
    comment TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    UNIQUE(request_id, approver_user_id)
);

CREATE TABLE IF NOT EXISTS disposal_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    request_id INTEGER NOT NULL UNIQUE REFERENCES approval_requests(id),
    method TEXT NOT NULL,
    witness_one INTEGER NOT NULL REFERENCES users(id),
    witness_two INTEGER NOT NULL REFERENCES users(id),
    disposed_quantity REAL NOT NULL CHECK(disposed_quantity > 0),
    certificate_digest TEXT NOT NULL,
    disposed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(witness_one <> witness_two)
);

CREATE TABLE IF NOT EXISTS inventory_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_code TEXT NOT NULL UNIQUE,
    vault_id INTEGER NOT NULL REFERENCES vault_locations(id),
    started_by INTEGER NOT NULL REFERENCES users(id),
    state TEXT NOT NULL CHECK(state IN ('draft','counting','reconciling','approved','closed','cancelled')),
    snapshot_version INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_review_counts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES inventory_reviews(id) ON DELETE CASCADE,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    observed_quantity REAL,
    observed_present INTEGER NOT NULL CHECK(observed_present IN (0,1)),
    counted_by INTEGER NOT NULL REFERENCES users(id),
    counted_at TEXT NOT NULL,
    note TEXT NOT NULL,
    UNIQUE(session_id, dossier_id)
);

CREATE TABLE IF NOT EXISTS incident_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_code TEXT NOT NULL UNIQUE,
    dossier_id INTEGER REFERENCES dossiers(id),
    intake_id INTEGER REFERENCES intake_batches(id),
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    state TEXT NOT NULL CHECK(state IN ('open','investigating','contained','resolved','dismissed')),
    detected_by INTEGER NOT NULL REFERENCES users(id),
    description TEXT NOT NULL,
    resolution TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dossier_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    event_type TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id),
    quantity_delta REAL NOT NULL DEFAULT 0,
    from_state TEXT,
    to_state TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    correlation_id TEXT,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dossier_events_dossier ON dossier_events(dossier_id, id);

CREATE TABLE IF NOT EXISTS secrecy_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_code TEXT NOT NULL UNIQUE,
    project_code TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    stage TEXT NOT NULL CHECK(stage IN ('research','production','patent_published','any')),
    suggested_level TEXT NOT NULL CHECK(suggested_level IN ('internal','confidential','restricted','top_secret')),
    basis TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrecy_policies_match
    ON secrecy_policies(active, project_code, asset_type, stage);

CREATE TABLE IF NOT EXISTS secrecy_adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adjustment_code TEXT NOT NULL UNIQUE,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    direction TEXT NOT NULL CHECK(direction IN ('upgrade','downgrade')),
    from_level TEXT NOT NULL CHECK(from_level IN ('internal','confidential','restricted','top_secret')),
    to_level TEXT NOT NULL CHECK(to_level IN ('internal','confidential','restricted','top_secret')),
    reason TEXT NOT NULL,
    basis TEXT NOT NULL,
    requested_by INTEGER NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    review_deadline TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','expired','cancelled')),
    policy_id INTEGER REFERENCES secrecy_policies(id),
    required_reviews INTEGER NOT NULL CHECK(required_reviews IN (1,2)),
    reviewed_at TEXT,
    reviewed_by INTEGER REFERENCES users(id),
    review_comment TEXT NOT NULL DEFAULT '',
    effective_at TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(from_level <> to_level)
);
CREATE INDEX IF NOT EXISTS idx_secrecy_adjustments_dossier ON secrecy_adjustments(dossier_id, id);
CREATE INDEX IF NOT EXISTS idx_secrecy_adjustments_state ON secrecy_adjustments(state, review_deadline);

CREATE TABLE IF NOT EXISTS secrecy_adjustment_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adjustment_id INTEGER NOT NULL REFERENCES secrecy_adjustments(id) ON DELETE CASCADE,
    reviewer_user_id INTEGER NOT NULL REFERENCES users(id),
    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
    comment TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    UNIQUE(adjustment_id, reviewer_user_id)
);

CREATE TABLE IF NOT EXISTS temporary_declassifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_code TEXT NOT NULL UNIQUE,
    dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
    access_session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    granted_by INTEGER NOT NULL REFERENCES users(id),
    granted_level TEXT NOT NULL CHECK(granted_level IN ('internal','confidential','restricted','top_secret')),
    purpose TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoke_reason TEXT NOT NULL DEFAULT '',
    revoked_by INTEGER REFERENCES users(id),
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_temp_declass_dossier ON temporary_declassifications(dossier_id, id);
CREATE INDEX IF NOT EXISTS idx_temp_declass_session ON temporary_declassifications(access_session_id);
CREATE INDEX IF NOT EXISTS idx_temp_declass_expires ON temporary_declassifications(expires_at);
"""

PERMISSIONS = [
    ("users.read", "查看用户", "users", "read"),
    ("users.write", "维护用户", "users", "write"),
    ("roles.read", "查看角色", "roles", "read"),
    ("roles.write", "维护角色", "roles", "write"),
    ("audit.read", "查看审计", "audit", "read"),
    ("jobs.run", "执行后台任务", "jobs", "run"),
    ("dossiers.read", "查看档案", "dossiers", "read"),
    ("dossiers.write", "维护档案", "dossiers", "write"),
    ("dossiers.disclose", "登记披露使用", "dossiers", "disclose"),
    ("dossiers.dispose", "执行合规处置", "dossiers", "dispose"),
    ("access_loans.manage", "管理查阅借阅", "access_loans", "manage"),
    ("inventory_review.manage", "管理载体盘点", "inventory_review", "manage"),
    ("approvals.decide", "审批高风险操作", "approvals", "decide"),
    ("vaults.read_sensitive", "查看精确密级库位", "vaults", "read_sensitive"),
    ("incidents.manage", "管理泄密事件", "incidents", "manage"),
    ("secrecy.read", "查看密级与调整历史", "secrecy", "read"),
    ("secrecy.adjust", "发起密级调整申请", "secrecy", "adjust"),
    ("secrecy.review_upgrade", "复核密级升级", "secrecy", "review_upgrade"),
    ("secrecy.review_downgrade", "复核密级降级", "secrecy", "review_downgrade"),
    ("secrecy.temp_declass", "签发临时解密授权", "secrecy", "temp_declass"),
    ("secrecy.policy.manage", "维护密级策略", "secrecy", "policy_manage"),
]


def database_path() -> Path:
    raw = os.getenv("ARCHIVE_DATABASE_PATH", str(DEFAULT_DB_PATH))
    return Path(raw).expanduser().resolve()


def _create_connection() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def get_connection() -> sqlite3.Connection:
    connection = getattr(_local, "connection", None)
    if connection is None:
        connection = _create_connection()
        _local.connection = connection
    return connection


def close_connection() -> None:
    connection = getattr(_local, "connection", None)
    if connection is not None:
        connection.close()
        _local.connection = None


@contextmanager
def transaction(*, immediate: bool = False) -> Iterator[sqlite3.Connection]:
    connection = get_connection()
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


def init_db() -> None:
    now = to_storage(utc_now())
    connection = get_connection()
    connection.executescript(SCHEMA)
    with transaction(immediate=True) as connection:
        for code, name, resource, action in PERMISSIONS:
            connection.execute(
                "INSERT OR IGNORE INTO permissions(code,name,resource,action) VALUES(?,?,?,?)",
                (code, name, resource, action),
            )
        roles = (
            ("administrator", "系统管理员", "拥有全部系统权限"),
            ("dossier_manager", "档案管理员", "维护档案、批次、位置、查阅借阅与载体盘点"),
            ("researcher", "研究人员", "查看档案并申请查阅借阅或登记对外合作披露使用"),
            ("approver", "风险审批人", "复核合规处置、位置解密与载体盘点调整"),
            ("auditor", "审计查看员", "只读查看档案事件和审计记录"),
        )
        for code, name, description in roles:
            connection.execute(
                "INSERT OR IGNORE INTO roles(code,name,description,is_system,created_at,updated_at) VALUES(?,?,?,1,?,?)",
                (code, name, description, now, now),
            )
        administrator = connection.execute("SELECT id FROM roles WHERE code='administrator'").fetchone()[0]
        connection.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id,permission_id,granted_at) SELECT ?,id,? FROM permissions",
            (administrator, now),
        )
        role_permissions = {
            "dossier_manager": [
                "dossiers.read", "dossiers.write", "dossiers.disclose", "dossiers.dispose",
                "access_loans.manage", "inventory_review.manage", "incidents.manage",
                "secrecy.read", "secrecy.adjust", "secrecy.temp_declass",
            ],
            "researcher": ["dossiers.read", "dossiers.disclose", "secrecy.read"],
            "approver": [
                "dossiers.read", "approvals.decide",
                "secrecy.read", "secrecy.review_upgrade", "secrecy.review_downgrade",
            ],
            "auditor": ["dossiers.read", "audit.read", "secrecy.read"],
        }
        for role_code, permission_codes in role_permissions.items():
            role_id = connection.execute("SELECT id FROM roles WHERE code=?", (role_code,)).fetchone()[0]
            placeholders = ",".join("?" for _ in permission_codes)
            connection.execute(
                f"INSERT OR IGNORE INTO role_permissions(role_id,permission_id,granted_at) "
                f"SELECT ?,id,? FROM permissions WHERE code IN ({placeholders})",
                (role_id, now, *permission_codes),
            )
        if connection.execute("SELECT COUNT(*) FROM secrecy_policies").fetchone()[0] == 0:
            default_policies = (
                ("SEC-DEFAULT-RD", "*", "*", "research", "restricted",
                 "默认制度：研发试验阶段技术秘密按机密管理", 900),
                ("SEC-DEFAULT-MFG", "*", "*", "production", "top_secret",
                 "默认制度：进入量产后工艺与配方价值升高，升为绝密", 900),
                ("SEC-DEFAULT-PUB", "*", "*", "patent_published", "internal",
                 "默认制度：专利公开日后技术细节已公开，降为内部", 900),
                ("SEC-SRC-MFG", "*", "源代码介质", "production", "top_secret",
                 "专项制度：量产源代码介质始终按绝密管理", 100),
            )
            for code, project_code, asset_type, stage, level, basis, priority in default_policies:
                connection.execute(
                    """INSERT OR IGNORE INTO secrecy_policies(
                           policy_code,project_code,asset_type,stage,suggested_level,basis,priority,active,created_at,updated_at
                       ) VALUES(?,?,?,?,?,?,?,1,?,?)""",
                    (code, project_code, asset_type, stage, level, basis, priority, now, now),
                )


def migrate_db() -> None:
    init_db()
