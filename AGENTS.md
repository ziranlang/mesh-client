# Mesh Client repository rules

- The canonical checkout is `~/Projects/ziranlang/packages/mesh-client`,
  on `master`, with origin `https://git.waozi.xyz/ziranlang/mesh-client.git`.
  This is a general Ziran library; keep it independent of Kryon's UI/runtime.
- This repository owns reusable Mesh client protocol and request behavior.
  The Mesh Go server and mesh node stay in the Mesh server repository;
  app storage, merge rules, and UI stay in each app; widgets stay in Kryon.
- Production implementation is Ziran `.zi`. C is allowed only in test harnesses
  and generated output. Do not add compatibility wrappers for old Kryon sync.
- Use direct API names such as `Client`, `Session`, `Login`, and `BearerRequest`.
- Preserve released wire formats and result codes, including legacy `daochi-*`
  signature/encryption contexts and `X-Daochi-*` headers. These are durable
  protocol bytes, not branding. Test against Mesh server fixtures when changing
  signed messages or protocol versions.
- Do not persist or log private keys or bearer tokens in this library. The app
  supplies key storage and token persistence.
- Run `sh tests/run.sh` and `git diff --check` before committing.
