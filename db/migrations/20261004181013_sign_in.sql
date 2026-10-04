-- +goose Up
-- Sign-in methods (design: From CodeShare › Sign-in): passkeys, Sign in with Apple,
-- Google and magic links. All end in the same session token; an account is created
-- only with a valid invitation, and signing in never grants keys.

-- Passkeys: the go-webauthn credential, stored whole as JSON as in CodeShare.
CREATE TABLE credentials (
    id           bytea PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 1023),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    data         jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX credentials_user_id_idx ON credentials (user_id);

-- WebAuthn ceremonies in flight, consumed once and only within five minutes. A
-- sign-up ceremony carries the invite that gated it and the id the new account
-- will get (the passkey's user handle); adding a passkey carries the signed-in user.
CREATE TABLE webauthn_sessions (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    data       jsonb NOT NULL,
    user_id    uuid,
    invite_id  text REFERENCES invites (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Apple and Google accounts, and verified e-mail addresses, linked to a user. One
-- user may have several; a provider subject belongs to one user. Linking is
-- explicit, from a signed-in session, never by a matching e-mail.
CREATE TABLE auth_identities (
    provider      text NOT NULL CHECK (provider IN ('apple', 'google', 'email')),
    subject       text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 320),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email         text CHECK (char_length(email) <= 320),
    -- Apple's refresh token, kept only to revoke the authorisation when the account
    -- is deleted (App Store guideline 5.1.1(v)).
    refresh_token text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);
CREATE INDEX auth_identities_user_id_idx ON auth_identities (user_id);

-- Magic links: a hash of the token, single use, 15 minutes. A sign-up link carries
-- the invite that gated it.
CREATE TABLE magic_links (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    email      text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
    invite_id  text REFERENCES invites (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX magic_links_email_idx ON magic_links (lower(email), created_at);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
