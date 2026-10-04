-- +goose Up
-- Fixes from the review of the phase 3 and 4 commits: what a session alone (one got
-- through someone else's inbox, or a phone since removed) may change is narrowed to
-- what the server can verify.

-- A deletion is a sealed tombstone, like any other write: the session JSON carries
-- deletedAt (docs/crypto.md), so only a holder of the practice key can delete.
ALTER TABLE practice_logs DROP CONSTRAINT practice_logs_check;
ALTER TABLE practice_logs ALTER COLUMN sealed SET NOT NULL;

-- Recovery boxes are signed by the identity key, so a session cannot replace them.
ALTER TABLE recovery_boxes ADD COLUMN signature bytea NOT NULL DEFAULT ''::bytea;
ALTER TABLE recovery_boxes ALTER COLUMN signature DROP DEFAULT;
ALTER TABLE recovery_boxes ADD CONSTRAINT recovery_boxes_signature_check CHECK (octet_length(signature) = 64) NOT VALID;

-- A session belongs to the device it registered, and ends with it.
ALTER TABLE sessions ADD COLUMN device_id uuid REFERENCES devices (id) ON DELETE CASCADE;
CREATE INDEX sessions_device_id_idx ON sessions (device_id);

-- A push token reaches one device only: a phone that signs in to another account
-- stops receiving the first one's nudges.
CREATE UNIQUE INDEX push_tokens_platform_token_key ON push_tokens (platform, token);

-- Server-issued, single-use nonces for Sign in with Apple and Google: a token is
-- accepted only for a nonce this server handed out in the last ten minutes.
CREATE TABLE auth_nonces (
    nonce_hash bytea PRIMARY KEY CHECK (octet_length(nonce_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Reports about someone outlive their account purge, without the link to it, so an
-- abuser cannot erase the evidence by deleting their account (design: Data export
-- and deletion, updated to match).
ALTER TABLE reports ALTER COLUMN reported_id DROP NOT NULL;
ALTER TABLE reports DROP CONSTRAINT reports_reported_id_fkey;
ALTER TABLE reports ADD CONSTRAINT reports_reported_id_fkey
    FOREIGN KEY (reported_id) REFERENCES users (id) ON DELETE SET NULL;

-- Purges are re-applied after a backup restore: only a hash of the user id is kept.
CREATE TABLE purge_log (
    user_hash  bytea PRIMARY KEY CHECK (octet_length(user_hash) = 32),
    purged_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
