-- Duongöndro schema v1. Shipped migrations are never edited; add a new file.
--
-- The database checks lengths; the service checks meaning (P-256 points,
-- Ed25519 signatures, UUIDv7 ids, clocks). Every table with a column that
-- references users must be handled by the export and the purge
-- (internal/store/gdpr.go); the GDPR integration tests derive the list of
-- such tables from information_schema, so a forgotten table fails them.

-- Part of every sync cursor. Change it after restoring a backup:
--   UPDATE database_generation SET id = gen_random_uuid();
CREATE TABLE database_generation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    id uuid NOT NULL
);
INSERT INTO database_generation (id) VALUES (gen_random_uuid());

CREATE TABLE users (
    id uuid PRIMARY KEY,
    display_name text NOT NULL,
    avatar_ref text CHECK (avatar_ref IS NULL OR char_length(avatar_ref) BETWEEN 1 AND 128),
    -- Ed25519 public key, pinned at sign-up from the signed acceptance.
    identity_pk bytea CHECK (identity_pk IS NULL OR octet_length(identity_pk) = 32),
    key_version integer NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    -- An anonymous node that takes a purged user's place in the invite tree
    -- and in others' reports. It has no name, identities or sessions.
    placeholder boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (placeholder AND display_name = '' AND avatar_ref IS NULL AND identity_pk IS NULL)
        OR (NOT placeholder AND char_length(display_name) BETWEEN 1 AND 64)
    )
);

CREATE TABLE auth_identities (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('apple', 'google', 'email')),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    email text CHECK (email IS NULL OR char_length(email) BETWEEN 3 AND 254),
    email_verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX auth_identities_user ON auth_identities (user_id);

-- Single-use sign-in links (15 minutes). Only the SHA-256 of the token.
CREATE TABLE magic_links (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    email text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX magic_links_expires ON magic_links (expires_at);

-- Issued by a verified magic link for an address without an account; usable
-- once, within an hour, only to redeem an invite.
CREATE TABLE signup_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    email text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX signup_tokens_expires ON signup_tokens (expires_at);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Uncompressed P-256 point 0x04 ‖ X ‖ Y.
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 65),
    tier text NOT NULL CHECK (tier IN ('hardware', 'tee', 'software')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, public_key),
    UNIQUE (id, user_id)
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, user_id) REFERENCES devices (id, user_id) ON DELETE CASCADE
);
CREATE INDEX sessions_user ON sessions (user_id);

-- The newest signed device-list statement per user (docs/crypto.md).
CREATE TABLE device_lists (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    version bigint NOT NULL CHECK (version >= 1),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 16384),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    identity_pk bytea NOT NULL CHECK (octet_length(identity_pk) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A 32-byte secret wrapped to one device. (user_id, key_version,
-- recipient_device, kind) are the AAD fields; the recipient device belongs to
-- user_id. Kinds 1 and 2 are only ever put by the user; kind 3 (share key) by
-- a friend too. The authenticator is stored as received.
CREATE TABLE wraps (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key_version integer NOT NULL CHECK (key_version >= 1),
    recipient_device uuid NOT NULL,
    kind smallint NOT NULL CHECK (kind IN (1, 2, 3)),
    sender_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    epk bytea NOT NULL CHECK (octet_length(epk) = 65),
    box bytea NOT NULL CHECK (octet_length(box) = 60),
    authenticator_kind text NOT NULL CHECK (authenticator_kind IN ('signature', 'enrol', 'self')),
    authenticator bytea NOT NULL CHECK (
        octet_length(authenticator) = CASE authenticator_kind WHEN 'signature' THEN 64 ELSE 32 END
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, recipient_device, kind, key_version, sender_id),
    FOREIGN KEY (recipient_device, user_id) REFERENCES devices (id, user_id) ON DELETE CASCADE,
    CHECK (kind = 3 OR sender_id = user_id)
);
CREATE INDEX wraps_sender ON wraps (sender_id);

CREATE TABLE recovery_boxes (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind smallint NOT NULL CHECK (kind IN (1, 2)),
    box bytea NOT NULL CHECK (octet_length(box) = 60),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind)
);

-- Sealed practice sessions: nonce(12) ‖ ciphertext ‖ tag(16) of JSON padded
-- to a multiple of 256 bytes, so 28 + 256·k bytes, at most 16 KiB.
CREATE TABLE practice_logs (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    sealed bytea NOT NULL CHECK (
        octet_length(sealed) BETWEEN 284 AND 16384 AND (octet_length(sealed) - 28) % 256 = 0
    ),
    key_version integer NOT NULL CHECK (key_version >= 1),
    -- The client's clock, whole milliseconds: the last-write-wins clock.
    client_updated_at timestamptz NOT NULL,
    deleted boolean NOT NULL DEFAULT false,
    -- The sync cursor: the writing transaction's id.
    xid xid8 NOT NULL DEFAULT pg_current_xact_id()
);
CREATE INDEX practice_logs_sync ON practice_logs (user_id, xid);

-- The newest signed streak statement per user and public practice.
CREATE TABLE streak_statements (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    practice text NOT NULL CHECK (practice ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    seq bigint NOT NULL CHECK (seq >= 0),
    day date NOT NULL,
    current integer NOT NULL CHECK (current >= 0),
    longest integer NOT NULL CHECK (longest >= current),
    deadline timestamptz NOT NULL,
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 1024),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, practice)
);

CREATE TABLE invites (
    id text PRIMARY KEY CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{8}$'),
    inviter_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the 32-byte auth key; the key itself is never stored.
    auth_key_hash bytea NOT NULL CHECK (octet_length(auth_key_hash) = 32),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 1024),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    mac bytea NOT NULL CHECK (octet_length(mac) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX invites_inviter ON invites (inviter_id);

-- The invite tree. No cascade from users: a purge replaces the purged user
-- with a placeholder here, so others' "invited by" stays consistent.
CREATE TABLE invite_redemptions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    invite_id text REFERENCES invites (id) ON DELETE SET NULL,
    inviter_id uuid NOT NULL REFERENCES users (id),
    invitee_id uuid NOT NULL REFERENCES users (id),
    -- The invitee's signed acceptance; dropped when the invitee is purged.
    acceptance_payload bytea CHECK (acceptance_payload IS NULL OR octet_length(acceptance_payload) BETWEEN 2 AND 1024),
    acceptance_signature bytea CHECK (acceptance_signature IS NULL OR octet_length(acceptance_signature) = 64),
    redeemed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (invite_id, invitee_id)
);
CREATE INDEX invite_redemptions_inviter ON invite_redemptions (inviter_id);
CREATE INDEX invite_redemptions_invitee ON invite_redemptions (invitee_id);

-- Symmetric, stored once per pair.
CREATE TABLE friendships (
    user_a uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    user_b uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_a, user_b),
    CHECK (user_a < user_b)
);
CREATE INDEX friendships_b ON friendships (user_b);

CREATE TABLE blocks (
    blocker_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blocked_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocks_blocked ON blocks (blocked_id);

-- No cascade on reported_id: a purge hands it to the placeholder so the
-- moderation record survives without the name.
CREATE TABLE reports (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reporter_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    reported_id uuid NOT NULL REFERENCES users (id),
    reason text NOT NULL CHECK (reason IN ('name', 'avatar', 'spam', 'other')),
    note text CHECK (note IS NULL OR char_length(note) <= 1000),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (reporter_id <> reported_id)
);
CREATE INDEX reports_reporter ON reports (reporter_id);
CREATE INDEX reports_reported ON reports (reported_id);

CREATE TABLE push_tokens (
    device_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    platform text NOT NULL CHECK (platform IN ('apns', 'fcm')),
    token text NOT NULL CHECK (char_length(token) BETWEEN 1 AND 4096),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, user_id) REFERENCES devices (id, user_id) ON DELETE CASCADE,
    UNIQUE (platform, token)
);
CREATE INDEX push_tokens_user ON push_tokens (user_id);

-- One poke per sender, friend and UTC day.
CREATE TABLE nudges (
    sender_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    recipient_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    day date NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sender_id, recipient_id, day)
);
CREATE INDEX nudges_recipient ON nudges (recipient_id);

-- Purged accounts, by SHA-256 of the user id only, so a restored backup can
-- re-apply purges.
CREATE TABLE purge_log (
    user_hash bytea PRIMARY KEY CHECK (octet_length(user_hash) = 32),
    purged_at timestamptz NOT NULL DEFAULT now()
);
