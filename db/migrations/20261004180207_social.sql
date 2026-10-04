-- +goose Up
-- Phase 4: invitations, friendships, blocks, reports and public streaks
-- (design: Social). Membership itself is sensitive, so nothing here is readable
-- without a session, except one invite record by the id its link carries.

-- A display name, shown to friends only.
ALTER TABLE users ADD COLUMN display_name text NOT NULL DEFAULT ''
    CHECK (char_length(display_name) <= 64);

-- Who brought whom, kept for moderation. A node outlives its user: a purged account
-- leaves an anonymous node (user_id NULL), so others' "invited by" stays consistent.
CREATE TABLE invite_tree (
    node_id    uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid UNIQUE REFERENCES users (id) ON DELETE SET NULL,
    parent_id  uuid REFERENCES invite_tree (node_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Reusable invitations. The link carries the id and a secret the server never
-- learns; the server keeps a hash of auth = HKDF(secret, invite-auth), which the
-- invitee presents to redeem, and the inviter's signed invite statement with
-- HMAC(pin, inviterIdentityPk), which the invitee checks first (docs/crypto.md).
CREATE TABLE invites (
    id         text PRIMARY KEY CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{8}$'),
    inviter_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    auth_hash  bytea NOT NULL CHECK (octet_length(auth_hash) = 32),
    payload    bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 4096),
    signature  bytea NOT NULL CHECK (octet_length(signature) = 64),
    mac        bytea NOT NULL CHECK (octet_length(mac) = 32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invites_inviter_idx ON invites (inviter_id, created_at);

-- Who redeemed which invite, with the invitee's signed acceptance.
CREATE TABLE invite_redemptions (
    invite_id  text NOT NULL REFERENCES invites (id) ON DELETE CASCADE,
    invitee_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    payload    bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 4096),
    signature  bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (invite_id, invitee_id)
);
CREATE INDEX invite_redemptions_invitee_idx ON invite_redemptions (invitee_id);

-- Friendships are mutual: one row each way, written and deleted together.
CREATE TABLE friendships (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    friend_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, friend_id),
    CHECK (user_id <> friend_id)
);
CREATE INDEX friendships_friend_idx ON friendships (friend_id);

-- A block ends the friendship and stops it coming back, in both directions.
CREATE TABLE blocks (
    blocker_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blocked_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocks_blocked_idx ON blocks (blocked_id);

-- Reports for moderation (required for user-generated names). The reporter's own
-- reports go when they purge their account; reports about someone go with them.
CREATE TABLE reports (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    reporter_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    reported_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    reason      text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reports_reporter_idx ON reports (reporter_id);
CREATE INDEX reports_reported_idx ON reports (reported_id);

-- The newest signed streak statement per user and public practice: exact payload
-- bytes and signature, so friends verify what they receive against the pinned key.
CREATE TABLE streaks (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    practice    text NOT NULL CHECK (practice ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    seq         bigint NOT NULL CHECK (seq >= 1),
    payload     bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 4096),
    signature   bytea NOT NULL CHECK (octet_length(signature) = 64),
    deadline_at timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, practice)
);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
