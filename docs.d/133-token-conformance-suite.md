# #133 — documentation for the token conformance suite

Contract and SDK surface unchanged (no new entry points, no ABI or
`CONTRACT_VERSION` change); this fragment records the new README text and
the new doc.

`README.md`:
- "Contract surface" gains a **Token compatibility** paragraph: any SEP-41
  token works (native SAC, issued-asset SAC such as USDC, custom SEP-41);
  amounts are raw token units and the contract never rescales or rounds;
  points at `docs/token-conformance.md`.
- "Getting started" updates the test count from 28 to 45 (main was already
  stale — the suite has been 31 since #17) and adds
  `cargo test --test token_conformance` with a one-line description.
- The documentation table links `docs/token-conformance.md`.

`docs/token-conformance.md` (new):
- the suite's four implementations and how each is deployed/funded;
- the per-token behaviour table (decimals, mint authority, balance
  storage, SEP-41 surface, transfer authorization, revert shape, absence
  of rescaling) and the read-across that the escrow sees no difference;
- amount/decimals guidance, including the 1.5-token-at-6-decimals case;
- the lifecycle matrix (which test pins what), each test tagged as
  running against every token type;
- recommended tokens for integrators (USDC's issued-asset SAC, native
  XLM, and SEP-41 tokens that revert on insufficient balance, require
  `from` authorization and charge no transfer fee);
- explicit out-of-scope note: issuer flags (clawback, auth-required) are
  tested separately, this suite is about implementations.
