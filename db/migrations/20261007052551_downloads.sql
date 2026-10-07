-- +goose Up
-- Downloads of the apps through the website's /download/<platform> links: one
-- running total per platform and UTC day, bumped by an upsert. It holds no
-- personal data (no address, user agent, account or time finer than the day),
-- so the GDPR export lists it as always empty and a purge has nothing to remove.
CREATE TABLE downloads (
    platform text NOT NULL CHECK (platform IN ('android')),
    day date NOT NULL,
    count bigint NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (platform, day)
);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
