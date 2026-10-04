# Website for duongondro.app

Static site for the apex and `www` hosts: landing page, privacy policy draft, the invite and add-friend pages shown when the app is not installed, and the app-link association files. Plain HTML and CSS; the only JavaScript is `invite.js`, used by `/i/` and `/f/`. It is licensed AGPL-3.0 like the rest of this repository.

## How it is served

The files are embedded into the API binary (`web/embed.go`, package `webfs`) and served by `internal/web.Handler()` on the apex and `www` hosts, behind Caddy. The embed patterns name `.well-known` explicitly, because `//go:embed web` would skip dot-directories. When adding a top-level file or directory, add it to the pattern in `embed.go`.

The handler:

- serves `/` and `/privacy/`, and the same invite page for every `/i/<id>` and the same add-friend page for every `/f/<id>`, with `Cache-Control: no-store`;
- serves `/.well-known/apple-app-site-association` as `application/json` with no redirect;
- caches fonts for a year, CSS, JS and icons for a week, pages for five minutes;
- sets a strict `Content-Security-Policy` (`default-src 'self'`), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on every response.

Because of that CSP there are no inline scripts or styles. Keep `style=` attributes and `<script>` blocks out of the HTML. Caddy must route the apex and `www` hosts to this handler, and should redirect `www` to the apex or serve both; it must not rewrite `/.well-known/` paths.

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
- `TEAMID` in `.well-known/apple-app-site-association`.
- The all-zero SHA-256 fingerprint in `.well-known/assetlinks.json`.
- App Store and Google Play buttons: the landing page has labelled placeholders ("Coming to the App Store"), and the invite pages say the links will appear. Replace them with real links; use the stores' official badges only as their guidelines require.
- The add-friend page tells people to choose "Add friend" in the app. Check that against the final wording of the screen. The invite page uses "I have an invite" from the Welcome screen.

## Fonts

Self-hosted only, no requests to Google or any other font service. IBM Plex Sans throughout, in Regular, SemiBold and Bold, split by script (Latin 1, Latin Extended and Cyrillic, which covers all eight launch languages) and loaded per `unicode-range`, so an English page downloads only the Latin 1 files. Taken from IBM's repository (github.com/IBM/plex, `packages/plex-sans/fonts/split/woff2`); licence in `fonts/IBMPlexSans-OFL.txt` (SIL OFL 1.1).

## Languages

English only for now. All copy is in the HTML files. The eight app languages (en, de, ru, uk, pl, cs, sk, hu) come later, most likely as one directory per language with its own `lang` attribute, and the invite pages' script strings will need the same treatment.
