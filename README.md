<!-- Modified by Mono Labs for the Monolythium IOTA Rust SDK, 2026. -->

# Monolythium IOTA Rust SDK

This repository is the maintained IOTA Rust SDK compatibility fork used by
Monolythium Core. It preserves IOTA's repository history and crate layout while
carrying the narrow protocol extensions required by Monolythium.

The reviewed upstream source and overlay paths are recorded in
[`UPSTREAM.yaml`](UPSTREAM.yaml). The official IOTA repository remains the
source for upstream improvements; Monolythium release branches adopt those
changes through reviewed merges.

This project is independently maintained and is not affiliated with or
endorsed by the IOTA Foundation.

## Crates

The workspace includes the IOTA SDK type, cryptography, transaction-builder,
GraphQL, gRPC, FFI, WASM, and language-binding crates. Existing IOTA crate names
remain unchanged so downstream updates stay auditable.

## Branches

- `mono/main` is the reviewed Monolythium integration branch.
- Feature branches contain focused changes proposed for `mono/main`.
- Untagged branches are not release artifacts.

## License

IOTA-origin files and Monolythium modifications are distributed under the
[Apache License 2.0](LICENSE). Attribution and source provenance are recorded in
[`NOTICE`](NOTICE).
