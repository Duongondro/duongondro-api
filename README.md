# duongondro-api

The Go backend for [Duongöndro](https://duongondro.app): track your meditation practice together with your friends, end-to-end encrypted and fully open source.

The server stores sealed blobs and signed public streaks. It never receives a practice count, a round number or a key: see [docs/crypto.md](docs/crypto.md).

## What is here

| Path | Contents |
| --- | --- |
| `docs/crypto.md` | Byte formats for sealed sessions, wraps, signed statements, invites, recovery |
| `docs/streaks.md` | The streak rules, including the jet-lag deadline |
| `testdata/vectors.json` | Crypto test vectors for the iOS and Android clients |
| `testdata/streak-cases.json` | Streak conformance cases every implementation must pass |
| `internal/e2ee` | Reference implementation of the crypto formats |
| `internal/streak` | Reference implementation of the streak rules |
| `internal/server` | HTTP routes (health and version so far) |
| `cmd/duongondro-api` | The server binary |

## Commands

```sh
make test      # gofmt, vet, tests
make run       # serve on 127.0.0.1:8080 (LISTEN_ADDR to change)
make vectors   # regenerate testdata/vectors.json after a format change
make release   # build; refuses a dirty tree
```

`GET /api/version` reports the commit the binary was built from (with `-dirty` for development builds), which the apps show in Settings.

## Design

The product and architecture are documented in the design repository (private for now). The crypto and streak specs here are the normative versions.

## Licence

GNU Affero General Public License v3.0. If you run a modified version of this server for others, you must offer them its source.
