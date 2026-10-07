# Website for duongondro.app

Static site for the apex and `www` hosts: landing page, privacy policy draft, and the invite, add-friend and magic-link pages shown when the app is not installed.

**Generated, do not edit.** Everything in this directory except `embed.go` and this README is the build of [Duongondro/duongondro-landing](https://github.com/Duongondro/duongondro-landing) (Astro, Tailwind CSS and Svelte), copied in by `make web`, which runs `npm ci && npm run build` in `../duongondro-landing` and syncs its `dist/` here. Change the site there, run `make web`, and commit `web/` together with a note of the landing commit it prints. The landing repository's README has the site's own rules.

## How it is served

The files are embedded into the API binary (`web/embed.go`, package `webfs`) and served by `internal/web.Handler()` for the hosts in `WEB_HOSTS` (`internal/server/website.go`): the first, `duongondro.app`, gets the site; the others (`www.`) a permanent redirect to it. No API route answers on those hosts. If the build gains a top-level file or directory, add it to the pattern in `embed.go`.

The association files, `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`, are not in this directory: the API generates them from its configuration (`APPLE_APP_IDS`, `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`; `internal/server/wellknown.go`), so the team id and signing fingerprint live in the server's environment, not in the repository.

The handler:

- serves `/` and `/privacy/`, and the same invite page for every `/i/<id>` (or `/I/`) and the same add-friend page for every `/f/<id>` (or `/F/`), with `Cache-Control: no-store`, and the sign-in fallback page at `/m` and `/m/*` (magic links are `https://duongondro.app/m#<token>` and normally open in the app);
- answers `/download/android` with a `302` to the newest APK on GitHub (`releases/latest/download/duongondro.apk`), `Cache-Control: no-store`, and counts nothing, so link previews and crawlers following a shared link change nothing;
- counts a download on `POST /download/android/count`, the beacon the landing page's script sends when someone clicks the button: `204`, `no-store`, limited to 10 a minute per client address (in memory, forgotten a minute later), not counted from crawler user agents or another site's page (`Sec-Fetch-Site`). The table `downloads` holds platform, UTC day and count, nothing about the visitor;
- answers `GET /download/android/count` with `{"count": N}` (`application/json`, `Cache-Control: public, max-age=60`), which the page shows under the button;
- caches `_assets/` (Astro's content-hashed scripts and stylesheet) and fonts for a year as immutable, the favicons, the link-preview image `og.png` and robots.txt for a week, pages for five minutes;
- sets a strict `Content-Security-Policy` (`default-src 'self'`), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on every response.

Because of that CSP there are no inline scripts or styles; `internal/web` tests that the build has none. Caddy proxies the apex and `www` to the API like `api.`; it must not rewrite `/.well-known/` paths.

The invite secret lives in the URL fragment. The invite page's script reads it in the browser; the server never sees it, and the page makes no requests.

## Preview locally

`npm run dev` in `../duongondro-landing`, or `go test ./internal/web/` for the routing and headers.

## Placeholders to fill before launch

Listed in the landing repository's README. The association files also need `APPLE_APP_IDS`, `ANDROID_PACKAGE` and `ANDROID_CERT_SHA256` in the server's environment.

## Fonts

Self-hosted only, no requests to Google or any other font service. IBM Plex Sans throughout, in Regular, SemiBold and Bold, split by script (Latin 1, Latin Extended and Cyrillic, which covers all eight launch languages) and loaded per `unicode-range`, so an English page downloads only the Latin 1 files. Taken from IBM's repository (github.com/IBM/plex, `packages/plex-sans/fonts/split/woff2`); licence in `fonts/IBMPlexSans-OFL.txt` (SIL OFL 1.1). They come with the landing build.

## Languages

English only for now. All copy is in the HTML files. The eight app languages (en, de, ru, uk, pl, cs, sk, hu) come later, most likely as one directory per language with its own `lang` attribute, and the invite pages' script strings will need the same treatment.
