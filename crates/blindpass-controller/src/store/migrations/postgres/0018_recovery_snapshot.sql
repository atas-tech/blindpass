-- SPDX-License-Identifier: AGPL-3.0-only
-- Historical recoveries deliberately receive no guessed archive context.
CREATE TABLE IF NOT EXISTS controller_recovery_snapshots (
    recovery_id TEXT PRIMARY KEY REFERENCES controller_recoveries(recovery_id),
    snapshot_epoch BIGINT NOT NULL CHECK (snapshot_epoch BETWEEN 1 AND 9007199254740991),
    snapshot_time_ms BIGINT NOT NULL CHECK (snapshot_time_ms BETWEEN 1 AND 9007199254740991),
    backup_digest TEXT NOT NULL CHECK (length(backup_digest)=43),
    signature TEXT NOT NULL CHECK (length(signature)=86)
);
