-- +goose Up
-- Optional profile fields from the onboarding. A username (3 to 32 of a-z, 0-9, dot
-- and underscore, stored lowercased, so unique regardless of case) names the
-- account's passkeys; friends never see it. A gender lets friends' phones pick the
-- grammatical forms of notifications about them.
ALTER TABLE users ADD COLUMN username text CHECK (username ~ '^[a-z0-9._]{3,32}$');
CREATE UNIQUE INDEX users_username_key ON users (username);
ALTER TABLE users ADD COLUMN gender text CHECK (gender IN ('male', 'female', 'nonbinary'));

-- A passkey sign-up may carry the profile the onboarding asked for first, so the
-- passkey is named after it; the ceremony keeps it until the account is made.
ALTER TABLE webauthn_sessions ADD COLUMN username text CHECK (username ~ '^[a-z0-9._]{3,32}$');
ALTER TABLE webauthn_sessions ADD COLUMN display_name text CHECK (char_length(display_name) <= 64);
ALTER TABLE webauthn_sessions ADD COLUMN gender text CHECK (gender IN ('male', 'female', 'nonbinary'));

-- +goose Down
-- Never rolled back; fix forward with a new migration.
