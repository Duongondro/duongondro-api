-- +goose Up
-- Admission codes: the way in for the first members, who have nobody to invite them.
-- `duongondro-api admit` prints fresh ones; the server keeps only a SHA-256 of each.
-- A code admits one account, which becomes a root of the invite tree (no inviter, no
-- friendship), and is then spent. A purged account leaves its code spent, without
-- the link to it.
CREATE TABLE admission_codes (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    code_hash  bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    used_at    timestamptz,
    CHECK (used_by IS NULL OR used_at IS NOT NULL)
);
CREATE INDEX admission_codes_used_by_idx ON admission_codes (used_by);

-- A sign-up ceremony or link is gated by an invitation or an admission code, never
-- both.
ALTER TABLE webauthn_sessions ADD COLUMN admission_id uuid REFERENCES admission_codes (id) ON DELETE CASCADE;
ALTER TABLE webauthn_sessions ADD CONSTRAINT webauthn_sessions_one_gate CHECK (invite_id IS NULL OR admission_id IS NULL);
ALTER TABLE magic_links ADD COLUMN admission_id uuid REFERENCES admission_codes (id) ON DELETE CASCADE;
ALTER TABLE magic_links ADD CONSTRAINT magic_links_one_gate CHECK (invite_id IS NULL OR admission_id IS NULL);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
