# Website for duongondro.app

Static site for the apex and `www` hosts: landing page, privacy policy draft, and the invite, add-friend and magic-link pages shown when the app is not installed. Plain HTML and CSS; the only JavaScript is `invite.js`, used by `/i/` and `/f/`, and `magic.js`, which strips the token from the address bar on `/m`. It is licensed AGPL-3.0 like the rest of this repository.

## How it is served

The files are embedded into the API binary (`web/embed.go`, package `webfs`) and served by `internal/web.Handler()` for the hosts in `WEB_HOSTS` (`internal/server/website.go`): the first, `duongondro.app`, gets the site; the others (`www.`) a permanent redirect to it. No API route answers on those hosts. When adding a top-level file or directory, add it to the pattern in `embed.go`.

The association files, `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`, are not in this directory: the API generates them from its configuration (`APPLE_APP_IDS`, `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`; `internal/server/wellknown.go`), so the team id and signing fingerprint live in the server's environment, not in the repository.

The handler:

- serves `/` and `/privacy/`, and the same invite page for every `/i/<id>` and the same add-friend page for every `/f/<id>`, with `Cache-Control: no-store`, and the sign-in fallback page at `/m` (magic links are `https://duongondro.app/m#<token>` and normally open in the app);
- caches fonts for a year, CSS, JS and icons for a week, pages for five minutes;
- sets a strict `Content-Security-Policy` (`default-src 'self'`), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on every response.

Because of that CSP there are no inline scripts or styles. Keep `style=` attributes and `<script>` blocks out of the HTML. Caddy proxies the apex and `www` to the API like `api.`; it must not rewrite `/.well-known/` paths.

The invite secret lives in the URL fragment. `invite.js` reads it in the browser; the server never sees it, and the page makes no requests.

## Preview locally

```sh
python3 -m http.server -d web 8000
```

`/i/<id>` and `/f/<id>` are not routed by the Python server. Open `http://localhost:8000/i/index.html#...` instead, but the id then has to come from the path, so for a full check run the API binary or `go test ./internal/web/`.

## Placeholders to fill before launch

- `[CONTACT EMAIL]` in every footer and in `privacy/index.html`.
- `[CONTROLLER NAME AND ADDRESS]` and `[HOSTING PROVIDER AND REGION, TO CONFIRM]` in `privacy/index.html`.
- The backup retention (30 days) is marked `[TO CONFIRM]`; the policy keeps its "Draft — not yet in force" banner until a lawyer has read it.
- `APPLE_APP_IDS`, `ANDROID_PACKAGE` and `ANDROID_CERT_SHA256` in the server's environment, for the association files.
- App Store and Google Play buttons: the landing page has labelled placeholders ("Coming to the App Store"), and the invite pages say the links will appear. Replace them with real links; use the stores' official badges only as their guidelines require.
- The add-friend page tells people to choose "Add friend" in the app. Check that against the final wording of the screen. The invite page uses "I have an invite" from the Welcome screen.

## Fonts

Self-hosted only, no requests to Google or any other font service. IBM Plex Sans throughout, in Regular, SemiBold and Bold, split by script (Latin 1, Latin Extended and Cyrillic, which covers all eight launch languages) and loaded per `unicode-range`, so an English page downloads only the Latin 1 files. Taken from IBM's repository (github.com/IBM/plex, `packages/plex-sans/fonts/split/woff2`); licence in `fonts/IBMPlexSans-OFL.txt` (SIL OFL 1.1).

## Languages

English only for now. All copy is in the HTML files. The eight app languages (en, de, ru, uk, pl, cs, sk, hu) come later, most likely as one directory per language with its own `lang` attribute, and the invite pages' script strings will need the same treatment.
