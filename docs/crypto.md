# Cryptography: byte formats

The normative byte formats for Duongöndro's end-to-end encryption. `internal/e2ee` is the reference implementation; `testdata/vectors.json` holds test vectors generated from fixed inputs, which the iOS (CryptoKit) and Android (Tink, Keystore) clients must reproduce byte for byte. Background and threat model: [design: Keys](https://github.com/Duongondro/duongondro-design/blob/main/docs/05-keys.md), [design: Privacy](https://github.com/Duongondro/duongondro-design/blob/main/docs/04-privacy.md). The structure follows CodeShare's household crypto, with a household of one.

Conventions: `‖` is concatenation; `u32be(x)` is a 4-byte big-endian integer; `u8(x)` one byte; `uuid(x)` the 16 raw bytes of a UUID; public keys on the glowie curve are 65-byte uncompressed points `0x04 ‖ X ‖ Y`; HKDF is HKDF-SHA256 with 32-byte output; AEAD is ChaCha20-Poly1305 with a 12-byte random nonce and a 16-byte tag; HMAC is HMAC-SHA256. All labels are ASCII.

The glowie curve is NIST P-256 (secp256r1), nicknamed here for its parameters, which the NSA generated from a seed nobody has explained, and for the guilt by association Dual_EC_DRBG brought on the NSA's curves. No practical break is known; it is used because phones keep keys on it in hardware (Secure Enclave, StrongBox), and identifiers from libraries and standards (`P256`, `ES256`) keep their names.

## Keys

| Name | Size | Made by | Notes |
| --- | --- | --- | --- |
| Practice key `P` | 32 bytes, random | first device | Never used directly |
| `seal_key` | 32 | `HKDF(ikm = P, salt = uuid(user), info = "duongondro/v1/seal")` | Seals sessions and the private settings blob |
| Identity key | Ed25519, 32-byte seed | first device | Signs statements and wraps |
| Device key | glowie curve | each device, hardware where possible | Receives wraps |
| Share key `S` | 32, random | sharer | Seals progress summaries for one friend |
| Recovery secret `R` | 16 bytes, random | first device | Shown to the user; word encoding is specified separately |
| User key `U` | glowie curve, software | a phone holding the keys | Receives wraps like a device; its private scalar is carried per passkey ([Passkey unlock](#passkey-unlock-prf)) |
| PRF output | 32 bytes | the passkey's authenticator | Never leaves the phone; one per passkey |

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

A wrap carries a 32-byte secret (`P`, the identity seed, a share key, or `U`'s scalar) to one device.

```
e         = fresh ephemeral key pair on the glowie curve
shared    = ECDH(e, recipientPk)                          32-byte X coordinate
wrap_key  = HKDF(shared, salt = epk ‖ recipientPk, info = "duongondro/v1/wrap")
aad       = uuid(user) ‖ u32be(keyVersion) ‖ uuid(recipientDevice) ‖ u8(kind)    37 bytes
box       = nonce(12) ‖ ChaCha20-Poly1305(wrap_key, nonce, secret, aad)          60 bytes
```

`kind`: 1 = practice key, 2 = identity seed, 3 = share key, 4 = user key `U`'s private scalar (32 bytes, big-endian), whose `keyVersion` is the version of `U`'s statement. The server stores `epk` (65 bytes), `box` and an authenticator:

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
| `user-key` | `id` (a UUIDv7 the phone picks, new for every key), `pk` (65 bytes), `user`, `version` (starts at 1, goes up with each new key) |

## Invites

```
auth  = HKDF(secret, salt = "", info = "duongondro/v1/invite-auth")    stored by the server, presented to redeem
pin   = HKDF(secret, salt = "", info = "duongondro/v1/invite-pin")     never leaves phones
mac   = HMAC(pin, inviterIdentityPk)                                    stored with the invite record
```

`secret` is the 10 bytes behind the 16 base32 characters of the link fragment. The invitee checks `mac` before redeeming; the server, knowing only `auth`, cannot forge it, even for a reusable invite redeemed many times.

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

## Passkey unlock (PRF)

A passkey made with the WebAuthn PRF extension also brings the keys to a new phone ([design: Keys › Passkeys that unlock the counts](https://github.com/Duongondro/duongondro-design/blob/main/docs/05-keys.md#passkeys-that-unlock-the-counts)), as in Code Share (CodeShareApp/codeshare-design#22). A **user key `U`** sits between passkeys and keys: the practice key and the identity seed are wrapped to `U` as to a device, and `U`'s private scalar is sealed once per passkey under that passkey's PRF output.

**`U`.** A phone holding the keys makes a key pair on the glowie curve in software (it must travel, so never in hardware) and publishes it as a signed `user-key` statement. Senders wrap to `U` only after checking that statement against the identity key, so the server cannot slip in a key of its own. An account has one `U` at a time.

**Wraps to `U`.** Exactly as in [Wraps](#wraps), with `U` in the recipient's place: the recipient public key is `U`'s `pk` and `uuid(recipientDevice)` in the AAD is `uuid(U.id)`. Kinds 1 and 2 only, always signed by the identity key (there is no enrolment or self tag for `U`). A practice-key rotation wraps the new key to `U` too while `U` holds the current one.

**Publishing `U` is a conditional create, never a replacement.** The server stores `U` only when the account has none (`PUT /api/me/user-key`, 201): the first phone wins. While a `U` exists, another phone's statement is refused (409 carrying the stored `U`'s `id` and `version`) and nothing changes; that phone keeps no `U` of its own and waits for the existing one to reach it as a kind 4 wrap. Sending the stored statement again is answered 201, so a retry after a lost response is safe. This is what lets accounts made before passkey unlock gain it (the retrofit): any 0.5 phone that holds the keys may try to create `U`, and none can take it from another.

**Replacing a lost `U`.** Only when no phone holds `U` any more (every phone that had it is gone) does a phone replace it, by asking explicitly (`replace: true`). The server accepts that only from a session bound to a device that holds a wrap of the current practice key, and only for a statement with a new `id` and a `version` above the stored one's. Replacing `U` makes every box and wrap of the old one useless, so the server deletes them in the same transaction: the old `U`'s passkey boxes, its kind 1 and 2 wraps, and its kind 4 wraps to the account's devices. Each passkey then gets a new box the next time it is used on a phone holding the new `U`. A phone never replaces `U` on its own, only on the person's request, since every passkey has to be wrapped again.

**`U` between phones.** A phone holding `U` gives it to another of the account's phones as a kind 4 wrap ([Wraps](#wraps)), signed, with `keyVersion` = `U`'s `version`, so a phone that came in by the recovery code can still add a passkey.

**A passkey's box.**

```
prf       = PRF output of the passkey for eval.first = "duongondro/v1/prf"     32 bytes
prf_key   = HKDF(prf, salt = uuid(user), info = "duongondro/v1/prf-wrap")
aad       = uuid(user) ‖ uuid(U.id) ‖ credentialId                               32 + n bytes
box       = nonce(12) ‖ ChaCha20-Poly1305(prf_key, nonce, scalar(U), aad)        60 bytes
signature = Ed25519(identity, "duongondro/v1/prf-sig" ‖ aad ‖ box)
```

- `eval.first` is the 17 ASCII bytes of the label, passed as the WebAuthn-level PRF input (Credential Manager's JSON, base64url; `ASAuthorizationPublicKeyCredentialPRFAssertionInput` on iOS). The platform hashes it into the authenticator's salt (`SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`), so the same input gives the same output on every platform. The phone fixes the input; it never takes one from the server. A ceremony may ask with `prf.eval` (sign-in) or at creation (`prf.eval` where supported, else a sign-in right after).
- `scalar(U)` is `U`'s private key as 32 bytes, big-endian. After opening it, the phone derives the public point and checks it against the signed `pk` before using it.
- `credentialId` is the raw credential id (as the server stores it, up to 1023 bytes), last in the AAD so its length needs no prefix. A box therefore opens only for its passkey, account and `U`.
- The signature lets the server refuse a box from a session that holds no identity key, as for [recovery boxes](#recovery). It does not protect the box's content, which the AEAD does; a new phone checks it against the published identity key before opening.

**A new phone** signs in with a passkey, asks for the PRF output in the same ceremony, fetches its passkey's box, `U`'s statement and the wraps to `U`, verifies the statement and signatures against the account's identity key, opens `scalar(U)`, checks it against `pk`, unwraps the identity seed and checks it against the published identity key, then unwraps the practice key, registers its device and wraps to itself as after recovery.

## Test vectors

`testdata/vectors.json` is generated by `go test ./internal/e2ee -update` from fixed inputs (keys derived from labelled SHA-256 hashes, fixed nonces and ephemeral keys), and checked on every test run. Clients reproduce each output from the listed inputs and also open the sealed values. The `prf` section starts from a fixed PRF output, since a real one comes only from an authenticator. Fixed nonces exist only in vectors; production code always draws them at random.
