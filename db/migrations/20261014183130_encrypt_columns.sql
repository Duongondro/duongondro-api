-- +goose Up
-- Encryption at rest (decision 17; docs/at-rest.md), step 1 of 4: the sealed
-- columns (<name>_encrypted, sealed by internal/atrest with an AAD binding table,
-- column, row and key) and the blind indexes (<name>_hash, HMAC-SHA256 of the
-- normalised value) beside the plain ones. Step 2, a Go migration, fills them from
-- the plain columns, which SQL cannot seal; step 3 drops the plain columns; step 4
-- rewrites the tables so the dropped values leave the files on disk too.
--
-- The sizes the plain columns checked are checked by the service before sealing.

ALTER TABLE users
    ADD COLUMN identity_public_key_encrypted bytea,
    ADD COLUMN display_name_encrypted bytea,
    ADD COLUMN username_encrypted bytea,
    ADD COLUMN username_hash bytea CHECK (octet_length(username_hash) = 32),
    ADD COLUMN gender_encrypted bytea;

ALTER TABLE devices
    ADD COLUMN public_key_encrypted bytea,
    ADD COLUMN public_key_hash bytea CHECK (octet_length(public_key_hash) = 32);

ALTER TABLE device_lists ADD COLUMN payload_encrypted bytea;
ALTER TABLE invites ADD COLUMN payload_encrypted bytea;
ALTER TABLE invite_redemptions ADD COLUMN payload_encrypted bytea;
ALTER TABLE reports ADD COLUMN reason_encrypted bytea;

ALTER TABLE streaks
    ADD COLUMN practice_encrypted bytea,
    ADD COLUMN practice_hash bytea CHECK (octet_length(practice_hash) = 32),
    ADD COLUMN payload_encrypted bytea;

ALTER TABLE credentials ADD COLUMN data_encrypted bytea;

ALTER TABLE webauthn_sessions
    ADD COLUMN username_encrypted bytea,
    ADD COLUMN display_name_encrypted bytea,
    ADD COLUMN gender_encrypted bytea;

ALTER TABLE auth_identities
    ADD COLUMN subject_encrypted bytea,
    ADD COLUMN subject_hash bytea CHECK (octet_length(subject_hash) = 32),
    ADD COLUMN email_encrypted bytea,
    ADD COLUMN email_hash bytea CHECK (octet_length(email_hash) = 32),
    ADD COLUMN refresh_token_encrypted bytea;

ALTER TABLE magic_links
    ADD COLUMN email_encrypted bytea,
    ADD COLUMN email_hash bytea CHECK (octet_length(email_hash) = 32);

ALTER TABLE push_tokens
    ADD COLUMN token_encrypted bytea,
    ADD COLUMN token_hash bytea CHECK (octet_length(token_hash) = 32);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
