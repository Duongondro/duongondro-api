-- +goose Up
-- Passkeys in Settings (design decision 25). A name the person may give a passkey,
-- sealed like every personal column (NULL: the app names it after its password
-- manager). And the passkey each session signed in with, so removing a passkey ends
-- the sessions it made; sessions from a magic link or from before this have none.
-- A backup holding either table fails the deploy fast instead of stalling it.
SET LOCAL lock_timeout = '10s';
ALTER TABLE credentials ADD COLUMN name_encrypted bytea;
ALTER TABLE sessions ADD COLUMN credential_id bytea REFERENCES credentials (id) ON DELETE CASCADE;
CREATE INDEX sessions_credential_id_idx ON sessions (credential_id);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
