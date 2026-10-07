-- name: CountDownload :exec
-- One more download today (UTC). A single statement, so concurrent requests
-- never lose an increment.
INSERT INTO downloads (platform, day, count) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 1)
ON CONFLICT (platform, day) DO UPDATE SET count = downloads.count + 1;

-- name: DownloadTotal :one
SELECT coalesce(sum(count), 0)::bigint AS total FROM downloads WHERE platform = $1;
