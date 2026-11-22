# Mesh Client

Ziran library for applications that sync with
[Mesh](https://mesh.ziran-lang.org). Package name and public namespace:
`mesh_client`. No server, mesh node, database, or UI implementation; no Kryon
dependency. Add it with
`ziran add https://git.waozi.xyz/ziranlang/mesh-client.git`.

## Quick start

Import `mesh_client/client` and `mesh_client/sync`, then:

- Set `Client.app_id`; supply a `Device` with a persisted Ed25519 key and signer,
  and a cryptographically random 64-digit hex nonce callback.
- Implement the host boundaries `SendRequest` (bounded HTTP) and `ReceiveEvent`
  (bounded WebSocket); every response buffer must be NUL terminated, including on
  error. A native host can adapt both to Ziran's curl HTTP and WebSocket modules.
- Persist `Session` to keep bearer tokens across restarts; account keys must
  outlive them.
- Own in the app: payload format, response merge, key store, platform transport.
  The library does not provision keys, revoke devices, store account data, or
  merge application records.

## Wire compatibility

Released protocol bytes keep their original spelling; renaming them would
invalidate signatures or stop existing users from decrypting:

- `daochi-*` signature contexts, `X-Daochi-*` HTTP headers;
- `daochi-record-v1` envelopes and `daochi-entity-v1/*` key derivation strings;
- `account-key-v1` and `ksync-account-key-v2` key files, account IDs, stored
  state, and result codes.

Old `daochi_client` imports and `Daochi*` source aliases are not provided.
Release APIs are `MeshRelease`, `MeshParseRelease`, `MeshSha256Matches`, and the
`MESH_RELEASE_*` limits. The package rename does not migrate stored data.

## Modules

Import as `mesh_client/<name>`; the export list in `ziran.toml` is the source
of truth.

| Module | Provides |
| --- | --- |
| `wire`, `protocol` | canonical challenge, login body, and signed message builders; canonical protocol constants |
| `url` | HTTPS and local network URL policy |
| `auth` | challenge parsing, signed login preparation, token parsing; `AUTH_2FA_REQUIRED` result |
| `client` | login and bearer requests with one fresh login after a `401`; `X-Mesh-2FA` pass-through |
| `account`, `async_account` | challenge-signed account deletion without transmitting a key backup; TOTP setup/confirm (`SetupTwoFactorTotp`, `ConfirmTwoFactorTotp`); async variant that never blocks the host event loop |
| `social` | alias and friend requests, actions, lists, stats |
| `transaction` | canonical device registration and protocol v6 transaction messages |
| `sync` | signed device registration and protocol v6 sync requests; `PrepareRequestHeader`, `SignTransactionHeader`, `PrepareSyncHeader` |
| `record` | encrypted profile v1 (`daochi-record-v1`) envelopes with canonical authenticated metadata; native, link libsodium |
| `record_v2` | compact single-encoded record envelope v2 (`MRV2`): ~25% smaller wire payload and ~2x faster encode/decode than v1 |
| `record_codec` | optional bounded gzip packing (`gzip-v1`) before encryption; native, link zlib |
| `entity`, `entity_native` | per-kind record keys and convergent 8 MiB chunk sealing; `entity_native` is SIMD accelerated through libsodium with byte-identical output |
| `keys`, `keys_native` | ML-DSA-44 key pair with SHA-256 public id, message signing, plain and passphrase-encrypted key files; `keys_native` adds Argon2id `mesh-account-key-v3` export/import (libsodium); `keys.ValidateIdentity` verifies an existing account and private-key proof without creating or replacing keys |
| `crypto` | PBKDF2 for key files, ChaCha20-Poly1305 and XChaCha20-Poly1305; passes SHA-256, HMAC-SHA-256, and hex from the [crypto](https://git.waozi.xyz/ziranlang/crypto) package |
| `crypto_native` | libsodium provider: bounded SHA-256, streaming digests, HMAC-SHA-256, XChaCha20-Poly1305, secure random bytes, buffer clearing, compatible Argon2id exports; same 24-byte nonces and appended authentication tags as existing encrypted content |
| `seed` | HKDF-SHA-256 master-seed key separation: isolated 32-byte subkeys from a 32-byte account master seed, so apps never need the raw ML-DSA-44 signing key |
| `envelope` | approved collection keys; the host stores the separate recipient key |
| `authorization`, `authorization_owner` | owner-signed authorization wire values; owner operations keep protocol v6 ML-DSA and registered-device signatures |
| `delegated`, `async_delegated` | key-bound session and scoped sync transports that never populate `HttpRequest.token`; poll-driven counterpart for session renewal and scoped requests |
| `async_client`, `async_sync` | polled login, bearer requests, and signed sync operations |
| `sync_flow` | resumable record pages, bounded transfer recovery, cursor validation |
| `events` | WebSocket URL and event validation, one event wait through a host callback |
| `release` | signed app releases (`daochi-zib-release-v2`) |
| `rewards` | node-issued rewards an account claims; the client names only the reward, never an amount, and re-claiming credits nothing |

## Native links

- `record`, `crypto_native`, `entity_native`, `keys_native`: link libsodium.
- `record_codec`: native hosts link zlib (`-lz`); Emscripten hosts use `-sUSE_ZLIB=1`.
- `keys` signing uses the [oqs](https://git.waozi.xyz/ziranlang/oqs) package.

## Registration hint

`Session.registration` remembers one successful device registration for up to an
hour between successful requests, scoped to the normalized node URL, account,
app, client, device key ID, and public key; sync then sends only its signed
transaction. The node still verifies both signatures and revocation on every
request. A missing-device response permits one fresh registration and a newly
signed transaction; revoked devices cannot register again. Clearing or renewing
the bearer session clears the hint. Hosts may save this public metadata with
`WriteRegistration` and restore it with `ReadRegistration`; it contains no
private key or bearer token.

## Async transport

`BeginRequest`/`PollRequest` and `BeginSync`/`PollSync` with `AsyncTransport`:
the poll returns `-1` while pending, `0` on transport failure, or `1` with the
HTTP status when complete; every completed response must be NUL terminated. Keep
the pending operation, session, client identity, signing contexts, body, and
extra header strings alive until completion or cancellation; each pending
operation has its own transport context. `CancelRequest` and `CancelSync`
release an active transfer and finish with `AUTH_REQUEST_FAILED`. Both modes
share the one-login retry after a `401`; sync modes share the registration and
transaction builders. A transport may resend a signed POST when a reused
connection drops after the node committed it; sync recognizes the exact replay
response and retries with a fresh nonce inside its bounded recovery budget. The
node's replay protection remains enforced.

## SyncFlow: accounts larger than one buffer

- After a capacity failure, sync switches to the server's encrypted record
  pages: it signs each page request, retries interrupted transfers, and
  validates forward cursor progress. One bounded response buffer spans pages;
  total account size has no fixed client buffer limit. Smaller record pages are
  tried when a page overflows; other failures keep the existing result codes. An
  optional transport `failure` callback reports `TRANSFER_FAILURE_CAPACITY`.
- Host callbacks load and save account-and-node-local `SyncPageState`, prepare
  the app's current encrypted records, and accept each response. `accept` must
  atomically merge records and persist the proposed next state; returning false
  does not advance durable progress. Only a terminal page may advance the
  account watermark. On restart the library resumes the saved cursor; cancel
  releases the current transfer and owned request memory. The `clock` callback
  refreshes transaction time between pages. These callbacks contain app storage
  policy, not page requests or transport retry decisions.
- `prepare` receives the maximum encrypted record count for the next upload,
  including any reduction after an oversized page; retain its returned body
  until the next `prepare` call or completion.
- Zero means download only: after overflow recovery or while resuming a partial
  download, uploads are omitted until the terminal page, so the download cursor
  cannot keep moving. A later sync uploads the retained local queue.

## Signed request headers

`sync.PrepareRequestHeader` prepares the same account/device signed v6
transaction for an exact HTTP method, path, and byte-counted body, including
empty GET/HEAD bodies and binary blob uploads. Hosts that already stream and
hash the body can use `sync.SignTransactionHeader` with an explicit
`transaction.SyncTransaction`; its account, app, and device must match the
supplied client. `PrepareSyncHeader` retains the existing POST sync behavior.
The host still owns transport, pinned-node policy, session/key storage, and
remote acknowledgment handling.

## Tests

```
sh tests/run.sh
```

Runs with the toolchain selected by `ziran pkg path ziran`; includes portable
`.zx` URL and wire tests and a saved `.zir` to `.zx` round trip. An ignored
`ziran.local.toml` selects the local compiler at `../../ziran`; otherwise
`ziran.lock` is used. Overrides: `ZIRAN_BIN` (launcher), `ZIRAN_DIR` and
`ZI2C_BIN` (compiler), `OQS_DIR`, `CRYPTO_DIR`.

## Pinned dependencies

| Dependency | Ref |
| --- | --- |
| [Ziran](https://git.waozi.xyz/ziranlang/ziran) toolchain | `5db3d3c39425d5dfe4bfe4a84e6f6e2e5a810ad0` |
| [oqs](https://git.waozi.xyz/ziranlang/oqs) | `22d2ddbdc236796953c905a05a2cebf5ab1b4ff3` |
| [crypto](https://git.waozi.xyz/ziranlang/crypto) | `cd4a75b3383e49dd5eb10a18b2181fe74b161880` |

## Portability

URL policy, wire builders, and signed device registration message construction
compile and run as portable `.zx`. The full HTTP client is not yet a `.zx`
bundle: host transport, digest, and signer callbacks need bundle capabilities.
Native Linux integration is tested; browser and Android transports are
application host work. Strings use Ziran's `TextView` and bounded
`TextUntilNul` instead of a native string-layout adapter.
