-- +goose Up
-- Optional grammatical gender, for conjugations in the Slavic languages (design:
-- Localisation › Grammatical gender). Shown to friends like the display name; NULL
-- means not given, and the phones then use the neutral forms.
ALTER TABLE users ADD COLUMN gender text CHECK (gender IN ('male', 'female', 'nonbinary'));

-- +goose Down
-- Never rolled back; fix forward with a new migration.
