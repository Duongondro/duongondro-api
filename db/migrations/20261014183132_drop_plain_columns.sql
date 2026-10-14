-- +goose Up
-- Encryption at rest, step 3 of 4: every row was sealed by step 2, so the plain
-- columns go, and the keys, uniqueness and lookups move to the blind indexes. From
-- here on the plain values exist only in the database's files until step 4 rewrites
-- them, and in backups taken before this deploy until they expire.

-- users: the username's uniqueness moves to its hash. An empty display name is NULL.
ALTER TABLE users
    DROP COLUMN identity_public_key,
    DROP COLUMN display_name,
    DROP COLUMN username,
    DROP COLUMN gender,
    ADD CONSTRAINT users_username_sealed CHECK ((username_hash IS NULL) = (username_encrypted IS NULL));
CREATE UNIQUE INDEX users_username_hash_key ON users (username_hash);

-- devices: one row per user and key, found by the key's hash.
ALTER TABLE devices DROP COLUMN public_key;
ALTER TABLE devices
    ALTER COLUMN public_key_encrypted SET NOT NULL,
    ALTER COLUMN public_key_hash SET NOT NULL,
    ADD CONSTRAINT devices_user_id_public_key_hash_key UNIQUE (user_id, public_key_hash);

-- Signed statements: the signature stays plain, the payload is sealed.
ALTER TABLE device_lists DROP COLUMN payload;
ALTER TABLE device_lists ALTER COLUMN payload_encrypted SET NOT NULL;
ALTER TABLE invites DROP COLUMN payload;
ALTER TABLE invites ALTER COLUMN payload_encrypted SET NOT NULL;
ALTER TABLE invite_redemptions DROP COLUMN payload;
ALTER TABLE invite_redemptions ALTER COLUMN payload_encrypted SET NOT NULL;

ALTER TABLE reports DROP COLUMN reason;
ALTER TABLE reports ALTER COLUMN reason_encrypted SET NOT NULL;

-- streaks: one per user and practice, keyed by the practice's hash.
ALTER TABLE streaks DROP CONSTRAINT streaks_pkey;
ALTER TABLE streaks DROP COLUMN practice, DROP COLUMN payload;
ALTER TABLE streaks
    ALTER COLUMN practice_encrypted SET NOT NULL,
    ALTER COLUMN practice_hash SET NOT NULL,
    ALTER COLUMN payload_encrypted SET NOT NULL,
    ADD PRIMARY KEY (user_id, practice_hash);

ALTER TABLE credentials DROP COLUMN data;
ALTER TABLE credentials ALTER COLUMN data_encrypted SET NOT NULL;

ALTER TABLE webauthn_sessions DROP COLUMN username, DROP COLUMN display_name, DROP COLUMN gender;

-- auth_identities: one per provider and subject, keyed by the subject's hash (for
-- the email provider, the address's hash, so subject_hash = email_hash).
ALTER TABLE auth_identities DROP CONSTRAINT auth_identities_pkey;
ALTER TABLE auth_identities DROP COLUMN subject, DROP COLUMN email, DROP COLUMN refresh_token;
ALTER TABLE auth_identities
    ALTER COLUMN subject_encrypted SET NOT NULL,
    ALTER COLUMN subject_hash SET NOT NULL,
    ADD PRIMARY KEY (provider, subject_hash),
    ADD CONSTRAINT auth_identities_email_sealed CHECK ((email_hash IS NULL) = (email_encrypted IS NULL));

-- magic_links: the per-address limit, lock and lookup go through the hash.
ALTER TABLE magic_links DROP COLUMN email;
ALTER TABLE magic_links
    ALTER COLUMN email_encrypted SET NOT NULL,
    ALTER COLUMN email_hash SET NOT NULL;
CREATE INDEX magic_links_email_hash_idx ON magic_links (email_hash, created_at);

-- push_tokens: a token reaches one device, found by its hash.
ALTER TABLE push_tokens DROP COLUMN token;
ALTER TABLE push_tokens
    ALTER COLUMN token_encrypted SET NOT NULL,
    ALTER COLUMN token_hash SET NOT NULL;
CREATE UNIQUE INDEX push_tokens_platform_token_hash_key ON push_tokens (platform, token_hash);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
