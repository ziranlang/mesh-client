# Mesh Client

Ziran library for applications that sync with Mesh. Package `mesh_client`.
This repository owns reusable client protocol and request behavior; it stays
independent of Kryon's UI/runtime. The Mesh Go server and mesh node live in the
Mesh server repository; app storage, merge rules, and UI live in each app;
widgets live in Kryon.

## Layout

- `*.zi` — protocol modules at the repo root (`module_roots = ["."]`; export
  list in `ziran.toml` is the source of truth).
- `tests/` — Ziran behavior tests plus C host-fixture tests; `tests/run.sh`
  runs everything.
- `ziran.toml` / `ziran.lock` — package manifest and locked dependencies.

## Commands

- Test: `sh tests/run.sh` (overrides `ZIRAN_BIN`, `ZIRAN_DIR`, `ZI2C_BIN`,
  `OQS_DIR`, `CRYPTO_DIR`; ignored `ziran.local.toml` selects `../../ziran`).
- Before committing: `sh tests/run.sh && git diff --check`.

## Pins

Toolchain `5db3d3c39425d5dfe4bfe4a84e6f6e2e5a810ad0`, oqs
`22d2ddbdc236796953c905a05a2cebf5ab1b4ff3`, crypto
`cd4a75b3383e49dd5eb10a18b2181fe74b161880` (see `ziran.toml`).

## Rules

- Canonical checkout `~/Projects/ziranlang/packages/mesh-client`, branch
  `master`, origin `https://git.waozi.xyz/ziranlang/mesh-client.git`.
- Production code is Ziran `.zi`; C only in test harnesses and generated
  output. No compatibility wrappers for old Kryon sync; use direct API names
  such as `Client`, `Session`, `Login`, `BearerRequest`.
- Preserve released wire formats and result codes, including legacy `daochi-*`
  signature/encryption contexts and `X-Daochi-*` headers: durable protocol
  bytes, not branding. Test against Mesh server fixtures when changing signed
  messages or protocol versions.
- Never persist or log private keys or bearer tokens; the app supplies key and
  token storage.

## Question -> file

- Wire formats, signature contexts, headers -> README "Wire compatibility",
  `wire.zi`, `protocol.zi`.
- Login, 2FA, tokens -> `auth.zi`, `client.zi`, `account.zi`.
- Sync transactions and pages -> `transaction.zi`, `sync.zi`, `sync_flow.zi`,
  `async_sync.zi`.
- Encryption and key files -> `crypto.zi`, `crypto_native.zi`, `keys.zi`,
  `keys_native.zi`, `entity.zi`, `seed.zi`.
- Host transport contract -> README "Async transport", `async_client.zi`.
- Test setup and overrides -> `tests/run.sh`.
