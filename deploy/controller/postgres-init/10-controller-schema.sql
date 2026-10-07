-- SPDX-License-Identifier: AGPL-3.0-only
-- First-initialization only (official image /docker-entrypoint-initdb.d). The
-- controller store lives in its own schema, selected by the role's search_path,
-- so the PostgreSQL backup (ADR 0011) can dump and verify exactly that schema.
-- The `public` schema is never used for controller state.
CREATE SCHEMA controller AUTHORIZATION blindpass;
ALTER ROLE blindpass SET search_path = controller;
