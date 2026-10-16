-- +goose Up
-- Validates the kind check passkey_unlock added NOT VALID: a scan of key_wraps
-- under SHARE UPDATE EXCLUSIVE, which leaves reads and writes running.
SET LOCAL lock_timeout = '10s';
ALTER TABLE key_wraps VALIDATE CONSTRAINT key_wraps_kind_check;

-- +goose Down
-- Never rolled back; fix forward with a new migration.
