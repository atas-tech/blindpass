-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE IF NOT EXISTS controller_clock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_observed_ms BIGINT NOT NULL
);
