-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS controller_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    tenant_id TEXT NOT NULL,
    issuer_epoch BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS operators (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    disabled_at BIGINT
);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    used_at BIGINT
);

CREATE TABLE IF NOT EXISTS operator_sessions (
    id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    refresh_hash TEXT NOT NULL UNIQUE,
    csrf_secret TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('browser', 'desktop')),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    rotated_from TEXT,
    family_id TEXT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    ring TEXT,
    api_key_hash TEXT NOT NULL,
    key_version BIGINT NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at BIGINT NOT NULL,
    rotated_at BIGINT,
    revoked_at BIGINT
);

CREATE TABLE IF NOT EXISTS secret_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    requester_agent_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    description TEXT NOT NULL,
    confirmation_code TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'submitted')),
    require_user_auth BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    submitted_at BIGINT,
    enc TEXT,
    ciphertext TEXT
);
CREATE INDEX IF NOT EXISTS secret_requests_expiry_idx ON secret_requests(expires_at);
CREATE INDEX IF NOT EXISTS secret_requests_owner_idx ON secret_requests(tenant_id, requester_agent_id, id);

CREATE TABLE IF NOT EXISTS exchanges (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    requester_agent_id TEXT NOT NULL,
    requester_public_key TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    fulfiller_hint TEXT NOT NULL,
    allowed_fulfiller_id TEXT,
    fulfilled_by TEXT,
    policy_decision_json TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'reserved', 'submitted', 'revoked')),
    prior_exchange_id TEXT,
    supersedes_exchange_id TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    enc TEXT,
    ciphertext TEXT
);
CREATE INDEX IF NOT EXISTS exchanges_expiry_idx ON exchanges(expires_at);
CREATE INDEX IF NOT EXISTS exchanges_owner_idx ON exchanges(tenant_id, requester_agent_id, id);

CREATE TABLE IF NOT EXISTS approvals (
    reference TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    requester_agent_id TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    fulfiller_hint TEXT NOT NULL,
    rule_id TEXT,
    reason TEXT NOT NULL,
    requester_ring TEXT,
    fulfiller_ring TEXT,
    approver_ids_json TEXT NOT NULL,
    approver_rings_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    decided_at BIGINT,
    decided_by TEXT
);
CREATE INDEX IF NOT EXISTS approvals_pending_idx ON approvals(tenant_id, status, expires_at);

CREATE TABLE IF NOT EXISTS exchange_lifecycle (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    exchange_id TEXT,
    event TEXT NOT NULL,
    actor_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS exchange_lifecycle_lookup_idx ON exchange_lifecycle(tenant_id, exchange_id, created_at);

CREATE TABLE IF NOT EXISTS policies (
    tenant_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    document_json TEXT NOT NULL,
    source TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_lookup_idx ON audit_events(tenant_id, created_at, id);

CREATE TABLE IF NOT EXISTS rate_windows (
    key TEXT PRIMARY KEY,
    window_start BIGINT NOT NULL,
    count BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS quota_counters (
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    day TEXT NOT NULL,
    count BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, action, day)
);
