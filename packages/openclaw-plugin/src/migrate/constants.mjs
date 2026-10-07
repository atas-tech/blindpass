export const MAX_FILE_BYTES = 1024 * 1024;
export const JOURNAL_NAME = ".blindpass-migrate.journal.json";
export const LOCK_NAME = ".blindpass-migrate.lock";
export const BACKUP_ROOT_NAME = ".blindpass-backup";
export const DEFAULT_PROVIDER_ALIAS = "blindpass";
export const STALE_JOURNAL_MS = 24 * 60 * 60 * 1000;
export const PLAN_NAME = ".blindpass-migrate.plan.json";
export const archivedJournalName = (migrationId) => `.blindpass-migrate.journal.${migrationId}.json`;
