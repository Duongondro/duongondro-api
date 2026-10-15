-- +goose Up
-- Adding an e-mail address to an existing account (POST /api/me/email): the mail
-- that confirms it is a magic-link row for that account, so it shares the
-- per-address limit, the lock, the code's guess count and the expiry with sign-in
-- mails. A row with user_id confirms an address for that account and never signs
-- anyone in; a row without it is a sign-in or sign-up link, as before. Deleting the
-- account deletes its pending confirmations.
SET LOCAL lock_timeout = '10s';
ALTER TABLE magic_links ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE magic_links ADD CONSTRAINT magic_links_confirm_no_gate
    CHECK (user_id IS NULL OR (invite_id IS NULL AND admission_id IS NULL AND NOT sign_up));
CREATE INDEX magic_links_user_id_idx ON magic_links (user_id, created_at) WHERE user_id IS NOT NULL;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
