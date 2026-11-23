# #133 — Token conformance suite

`contracts/escrow/tests/token_conformance.rs` runs every escrow lifecycle
against four token implementations: the native SAC, an issued-asset SAC
with no issuer flags, and a test-only SEP-41 contract at 6 and 18 decimals.
It pins raw-unit amount handling (no rescaling or rounding at any
precision), asserts the facts behind `docs/token-conformance.md`'s
behaviour table, and proves the custom variants implement the full SEP-41
surface. CI runs the suite as its own step. No contract change; 45/45
tests and the wasm release build pass. Closes #133.
