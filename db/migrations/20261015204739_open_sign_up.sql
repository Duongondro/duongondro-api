-- +goose Up
-- Open sign-up (design decision 20): a sign-up ceremony or magic link says it is one
-- explicitly, instead of being recognised by the invitation or admission code it
-- carries, so one with neither (OPEN_SIGNUP=true) is told apart from a sign-in or
-- from adding a passkey. Rows from before this have false and are recognised by their
-- invite or code, as before.
SET LOCAL lock_timeout = '10s';
ALTER TABLE webauthn_sessions ADD COLUMN sign_up boolean NOT NULL DEFAULT false;
ALTER TABLE magic_links ADD COLUMN sign_up boolean NOT NULL DEFAULT false;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
