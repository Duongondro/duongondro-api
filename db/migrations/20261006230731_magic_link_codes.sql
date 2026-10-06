-- +goose Up
-- A magic link also carries a code of 8 Crockford base32 characters (40 bits), for
-- typing into the app when the link opens elsewhere: a SHA-256 over the row's token
-- hash and the code, on the same single-use row. Five wrong codes kill the row, link
-- and all; a newer link to the same address kills the older ones, so asking again
-- does not add guesses. Dead rows stay until they expire, so the per-address limit
-- still counts them.
ALTER TABLE magic_links ADD COLUMN code_hash bytea CHECK (octet_length(code_hash) = 32);
ALTER TABLE magic_links ADD COLUMN wrong_codes smallint NOT NULL DEFAULT 0 CHECK (wrong_codes BETWEEN 0 AND 5);
ALTER TABLE magic_links ADD COLUMN dead_at timestamptz;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
