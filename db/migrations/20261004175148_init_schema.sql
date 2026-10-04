-- +goose Up
-- Phase 3: accounts, devices, key wraps, the signed device list, sealed practice
-- logs and recovery boxes. The server stores ciphertext and public keys only; it
-- checks sizes, the glowie curve (NIST P-256) points and Ed25519 signatures, and
-- nothing else (docs/crypto.md).

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    -- Ed25519 identity key, set once by the first device; it signs the device
    -- list and identity-signed wraps. NULL until then.
    identity_public_key bytea CHECK (octet_length(identity_public_key) = 32),
    -- Version of the practice key P; sealed logs and practice-key wraps carry it.
    key_version         integer NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- Bearer tokens, stored as SHA-256. Sessions never expire; signing out deletes one.
CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- One per phone: a glowie curve point that receives wraps, and the storage tier
-- its private key was created in (docs: design Keys).
CREATE TABLE devices (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 65),
    tier       text NOT NULL CHECK (tier IN ('hardware', 'tee', 'software')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, public_key)
);

-- The newest signed device list per user: the exact payload bytes and their
-- signature, so verifiers check the bytes they receive. Versions only go up.
CREATE TABLE device_lists (
    user_id    uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    version    bigint NOT NULL CHECK (version >= 1),
    payload    bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 16384),
    signature  bytea NOT NULL CHECK (octet_length(signature) = 64),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A 32-byte secret (kind 1 practice key, 2 identity seed) wrapped to one of the
-- owner's devices. The authenticator is an Ed25519 signature by the owner's
-- identity key, or an HMAC tag (enrolment from a QR, or a device wrapping to
-- itself) that only the devices can check.
CREATE TABLE key_wraps (
    device_id     uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    kind          smallint NOT NULL CHECK (kind IN (1, 2)),
    key_version   integer NOT NULL CHECK (key_version >= 1),
    ephemeral_key bytea NOT NULL CHECK (octet_length(ephemeral_key) = 65),
    box           bytea NOT NULL CHECK (octet_length(box) = 60),
    auth_type     text NOT NULL CHECK (auth_type IN ('signature', 'enrol', 'self')),
    authenticator bytea NOT NULL CHECK (
        (auth_type = 'signature' AND octet_length(authenticator) = 64)
        OR (auth_type IN ('enrol', 'self') AND octet_length(authenticator) = 32)),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, kind, key_version)
);

-- Sealed practice sessions. The id is the client's (UUIDv7); last write wins on the
-- client's clock. A delete keeps a tombstone without its content, so other devices
-- learn of it through sync. Every write sets xid = pg_current_xact_id(), which the
-- sync cursor reads (CodeShare's scheme).
CREATE TABLE practice_logs (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    sealed            bytea CHECK (octet_length(sealed) BETWEEN 284 AND 16412),
    key_version       integer NOT NULL CHECK (key_version >= 1),
    client_updated_at timestamptz NOT NULL,
    deleted_at        timestamptz,
    xid               xid8 NOT NULL DEFAULT pg_current_xact_id(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK ((deleted_at IS NULL) = (sealed IS NOT NULL))
);
CREATE INDEX practice_logs_user_xid_idx ON practice_logs (user_id, xid);

-- The practice key and identity seed sealed under the recovery code, one box each.
CREATE TABLE recovery_boxes (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       smallint NOT NULL CHECK (kind IN (1, 2)),
    box        bytea NOT NULL CHECK (octet_length(box) = 60),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind)
);

-- Identifies this database's history for the sync cursor: a restored dump gets a new
-- id (UPDATE database_generation SET id = uuidv7()), and clients then sync in full.
CREATE TABLE database_generation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    id        uuid NOT NULL DEFAULT uuidv7()
);
INSERT INTO database_generation DEFAULT VALUES;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
