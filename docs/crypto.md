# Cryptography: byte formats

The normative byte formats for Duongöndro's end-to-end encryption. `internal/e2ee` is the reference implementation; `testdata/vectors.json` holds test vectors generated from fixed inputs, which the iOS (CryptoKit) and Android (Tink, Keystore) clients must reproduce byte for byte. Background and threat model: [design: Keys](https://github.com/Duongondro/duongondro-design/blob/main/docs/05-keys.md), [design: Privacy](https://github.com/Duongondro/duongondro-design/blob/main/docs/04-privacy.md). The structure follows CodeShare's household crypto, with a household of one.

Conventions: `‖` is concatenation; `u32be(x)` is a 4-byte big-endian integer; `u8(x)` one byte; `uuid(x)` the 16 raw bytes of a UUID; P-256 public keys are 65-byte uncompressed points `0x04 ‖ X ‖ Y`; HKDF is HKDF-SHA256 with 32-byte output; AEAD is ChaCha20-Poly1305 with a 12-byte random nonce and a 16-byte tag; HMAC is HMAC-SHA256. All labels are ASCII.

## Keys

| Name | Size | Made by | Notes |
| --- | --- | --- | --- |
| Practice key `P` | 32 bytes, random | first device | Never used directly |
| `seal_key` | 32 | `HKDF(ikm = P, salt = uuid(user), info = "duongondro/v1/seal")` | Seals sessions and the private settings blob |
| Identity key | Ed25519, 32-byte seed | first device | Signs statements and wraps |
| Device key | P-256 | each device, hardware where possible | Receives wraps |
| Share key `S` | 32, random | sharer | Seals progress summaries for one friend |
| Profile key `K` | 32, random, with a version | first device; a new one on every unfriend or block | Seals the profile for friends |
| Recovery secret `R` | 16 bytes, random | first device | Shown to the user; word encoding is specified separately |

## Sealed session

```
seal_key  = HKDF(P, salt = uuid(user), info = "duongondro/v1/seal")
padded    = json ‖ 0x80 ‖ 0x00…   (zero bytes up to the next multiple of 256)
aad       = uuid(session) ‖ uuid(user) ‖ u32be(keyVersion)          36 bytes
sealed    = nonce(12) ‖ ChaCha20-Poly1305(seal_key, nonce, padded, aad)   (ciphertext ‖ tag)
```

`json` is the session as one UTF-8 JSON object. Times are Unix milliseconds; days are `YYYY-MM-DD`.

| Field | Type | Meaning |
|---|---|---|
| `practice` | string | Catalogue id (`dorje-sempa`) or a custom practice's id |
| `count` | integer | Repetitions in this sitting (a mala's worth, or 0 for streak-only) |
| `day` | string | The civil day the session counts for; written for other readers, derivable from `start`, `tz` and `chosenDay` |
| `chosenDay` | string, optional | Present when the session counts for another day than its start's: the night rule (logged before 02:00, or within 40 minutes of a session that counted so, counts for the previous day) or the after-midnight sheet |
| `start` | integer | When the sitting started |
| `exact` | boolean, optional | Whether `start` was recorded (true) or estimated; default false |
| `tz` | string | IANA time zone the session was logged in |
| `loggedAt` | integer, optional | When it was logged; default `start` |
| `updatedAt` | integer | Last change; must equal the outer `updatedAt`, which a client checks, so the server cannot replay an old blob under a newer time. The outer time is sent as exactly this millisecond (RFC 3339 with three fractional digits), and both sides round a clock reading to the nearest millisecond, never down: a stored time can sit a hair below its millisecond |
| `deletedAt` | integer, optional | Present on a tombstone |
| `practiceName` | string, optional | A custom practice's name, so another phone can show it |

Readers ignore unknown fields (`minutes` and `note` are reserved for later versions). A deletion is sealed like any other write, as a tombstone whose json carries `deletedAt` and `updatedAt` and may omit the rest, so only a holder of the practice key can delete a session. Padding hides the length of notes and names from the server; unpadding strips trailing zero bytes and then exactly one `0x80`, and fails if that byte is missing. The AAD binds a blob to one session id, one user and one key version, so the server cannot move or replay it under another identity.

## Wraps

A wrap carries a 32-byte secret (`P`, the identity seed, or a share key) to one device.

```
e         = fresh ephemeral P-256 key pair
shared    = ECDH(e, recipientPk)                          32-byte X coordinate
wrap_key  = HKDF(shared, salt = epk ‖ recipientPk, info = "duongondro/v1/wrap")
aad       = uuid(user) ‖ u32be(keyVersion) ‖ uuid(recipientDevice) ‖ u8(kind)    37 bytes
box       = nonce(12) ‖ ChaCha20-Poly1305(wrap_key, nonce, secret, aad)          60 bytes
```

`kind`: 1 = practice key, 2 = identity seed, 3 = share key, 4 = profile key (sent to a friend's devices; `keyVersion` is the profile key's version). The server stores `epk` (65 bytes), `box` and an authenticator:

| Authenticator | Used when | Value |
| --- | --- | --- |
| Signature | normal case: the sender has an identity key | `Ed25519(identity, "duongondro/v1/wrap-sig" ‖ epk ‖ box ‖ aad ‖ recipientPk)` |
| Enrolment tag | a new device's first wrap, before it has an identity key | `HMAC(HKDF(s, salt = recipientPk, info = "duongondro/v1/enrol-auth"), epk ‖ box ‖ aad ‖ recipientPk)`, `s` = the QR secret |
| Self tag | a device wrapping to itself | `HMAC(HKDF(ECDH(d, d·G), salt = uuid(user), info = "duongondro/v1/self-auth"), epk ‖ box ‖ aad ‖ recipientPk)` |

A device verifies the authenticator before it decrypts anything.

## Signed statements

```
message   = "duongondro/v1/" ‖ type ‖ "\n" ‖ payload
signature = Ed25519(identity, message)
```

`payload` is compact UTF-8 JSON with keys in lexicographic order, integers only (times are Unix milliseconds), byte strings as unpadded base64url, and UUIDs as lowercase strings with hyphens (`b67fe412-4108-71f1-b85c-4c0606f45a8a`), the form the server compares against. The server stores and forwards the exact payload bytes; verifiers check the signature over the bytes they received and only then parse, so no client ever re-serialises JSON to verify.

| Type | Payload keys |
| --- | --- |
| `device-list` | `devices` (array of `{id, pk, tier}`; `tier` is `hardware`, `tee` or `software`), `issuedAt`, `user`, `version` |
| `streak` | `current`, `day`, `deadline`, `longest`, `practice`, `seq`, `user` (`current` and `longest` count tracked days only) |
| `invite` | `expiresAt`, `inviteId`, `inviter`, `inviterIdentityPk` |
| `acceptance` | `inviteId`, `invitee`, `inviteeIdentityPk` |

## Invites

```
auth  = HKDF(secret, salt = "", info = "duongondro/v1/invite-auth")    stored by the server, presented to redeem
pin   = HKDF(secret, salt = "", info = "duongondro/v1/invite-pin")     never leaves phones
mac   = HMAC(pin, inviterIdentityPk)                                    stored with the invite record
```

`secret` is the 10 bytes behind the 16 base32 characters of the link fragment. The invitee checks `mac` before redeeming; the server, knowing only `auth`, cannot forge it, even for a reusable invite redeemed many times.

## Profiles

*Specified, not yet implemented* (design: Social › Profiles).

```
padded  = json ‖ 0x80 ‖ 0x00…   (zero bytes up to the next multiple of 64)
aad     = uuid(user) ‖ u32be(profileKeyVersion)                     20 bytes
profile = nonce(12) ‖ ChaCha20-Poly1305(K, nonce, padded, aad)
```

`json` holds `name` (string, at most 64 code points), `gender` (optional: `male`, `female` or `nonbinary`) and `updatedAt` (Unix milliseconds). The server stores the latest `profile` per user with its version, checks only its size, and serves it to the user and their friends. A friend receives `K` as a wrap of kind 4; the person's own devices keep the friends' keys they received in their private settings blob, sealed under `seal_key`.

An invite carries a snapshot for the screen before accepting:

```
invite_profile_key = HKDF(secret, salt = "", info = "duongondro/v1/invite-profile")
invite_profile     = nonce(12) ‖ ChaCha20-Poly1305(invite_profile_key, nonce, padded, aad = ascii(inviteId))
```

stored with the invite record and opened by the invitee only after the invite's `mac` checks. It is never used once the two are friends.

## Recovery

```
recovery_key = HKDF(R, salt = uuid(user), info = "duongondro/v1/recovery")
aad          = uuid(user) ‖ u8(kind)
box          = nonce(12) ‖ ChaCha20-Poly1305(recovery_key, nonce, secret, aad)
```

One box per kind (practice key, identity seed), stored by the server. Each box is signed by the identity key, so a session alone (one got through someone else's inbox) cannot replace it:

```
signature    = Ed25519(identity, "duongondro/v1/recovery-sig" ‖ uuid(user) ‖ u8(kind) ‖ box)
```

## Test vectors

`testdata/vectors.json` is generated by `go test ./internal/e2ee -update` from fixed inputs (keys derived from labelled SHA-256 hashes, fixed nonces and ephemeral keys), and checked on every test run. Clients reproduce each output from the listed inputs and also open the sealed values. Fixed nonces exist only in vectors; production code always draws them at random.
