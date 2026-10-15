-- +goose Up
-- Passkeys that unlock the counts (design decision 23, docs/crypto.md › Passkey
-- unlock). Every table holds only what the phones sealed end to end, and signatures.
-- A backup holding a table fails the deploy fast instead of stalling it.
SET LOCAL lock_timeout = '10s';

-- The user key U, one per account: the signed user-key statement (sealed at rest,
-- since it carries a public key) and its id and version, which the wraps below
-- point to. A new U replaces the row, and its boxes and wraps go with the old one.
CREATE TABLE user_keys (
    user_id           uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    id                uuid NOT NULL UNIQUE,
    version           bigint NOT NULL CHECK (version >= 1),
    payload_encrypted bytea NOT NULL,
    signature         bytea NOT NULL CHECK (octet_length(signature) = 64),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- The practice key (1) and identity seed (2) wrapped to U, always signed by the
-- identity key.
CREATE TABLE user_key_wraps (
    user_key_id   uuid NOT NULL REFERENCES user_keys (id) ON DELETE CASCADE,
    kind          smallint NOT NULL CHECK (kind IN (1, 2)),
    key_version   integer NOT NULL CHECK (key_version >= 1),
    ephemeral_key bytea NOT NULL CHECK (octet_length(ephemeral_key) = 65),
    box           bytea NOT NULL CHECK (octet_length(box) = 60),
    signature     bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_key_id, kind, key_version)
);

-- U's scalar sealed under one passkey's PRF output. Removing the passkey or
-- replacing U deletes it.
CREATE TABLE passkey_boxes (
    credential_id bytea PRIMARY KEY REFERENCES credentials (id) ON DELETE CASCADE,
    user_key_id   uuid NOT NULL REFERENCES user_keys (id) ON DELETE CASCADE,
    box           bytea NOT NULL CHECK (octet_length(box) = 60),
    signature     bytea NOT NULL CHECK (octet_length(signature) = 64),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX passkey_boxes_user_key_id_idx ON passkey_boxes (user_key_id);

-- Kind 4 carries U's scalar from one phone to another.
ALTER TABLE key_wraps DROP CONSTRAINT key_wraps_kind_check;
ALTER TABLE key_wraps ADD CONSTRAINT key_wraps_kind_check CHECK (kind IN (1, 2, 4));

-- +goose Down
-- Never rolled back; fix forward with a new migration.
