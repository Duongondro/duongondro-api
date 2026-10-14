-- +goose NO TRANSACTION
-- +goose Up
-- Encryption at rest, step 4 of 4: a dropped column's values, and the row versions
-- step 2's updates left behind, stay in the table's files until the table is
-- rewritten. VACUUM FULL rewrites each table that held plain personal values, so the
-- data directory no longer holds them either. It locks each table while it runs,
-- which is fine here: the service is stopped while `server migrate` runs, and the
-- tables are small. (VACUUM cannot run in a transaction, hence NO TRANSACTION.)
VACUUM FULL users;
VACUUM FULL devices;
VACUUM FULL device_lists;
VACUUM FULL invites;
VACUUM FULL invite_redemptions;
VACUUM FULL reports;
VACUUM FULL streaks;
VACUUM FULL credentials;
VACUUM FULL webauthn_sessions;
VACUUM FULL auth_identities;
VACUUM FULL magic_links;
VACUUM FULL push_tokens;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
