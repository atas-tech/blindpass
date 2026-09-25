-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE controller_meta
    ALTER COLUMN issuer_epoch TYPE BIGINT USING issuer_epoch::BIGINT;
