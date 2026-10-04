-- +goose Up
-- Push (design: Social › Nudges, Backend and sync › Push). The server only ever
-- pushes public data: friends' names, practice ids and day counts, as loc-key and
-- loc-args the phone renders in its own language.

-- One token per device, APNs (iOS) or FCM (Android); dropped when the provider
-- reports it unregistered.
CREATE TABLE push_tokens (
    device_id  uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    platform   text NOT NULL CHECK (platform IN ('apns', 'apns-sandbox', 'fcm')),
    token      text NOT NULL CHECK (char_length(token) BETWEEN 1 AND 4096),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- "Done today" pushes are opt-in per friend: set on the recipient's row of the
-- friendship.
ALTER TABLE friendships ADD COLUMN notify_done boolean NOT NULL DEFAULT false;

-- Pokes: one per sender, recipient and UTC day.
CREATE TABLE nudges (
    sender_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    recipient_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    day          date NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sender_id, recipient_id, day)
);
CREATE INDEX nudges_recipient_idx ON nudges (recipient_id);

-- Streak-at-risk pushes for public streaks go two hours before the signed deadline,
-- once per statement.
ALTER TABLE streaks ADD COLUMN at_risk_sent_seq bigint NOT NULL DEFAULT 0;
CREATE INDEX streaks_deadline_idx ON streaks (deadline_at);

-- +goose Down
-- Never rolled back; fix forward with a new migration.
