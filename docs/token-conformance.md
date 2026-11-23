# Token conformance

Added by issue #133 (ROADMAP Phase E7). This document is the behaviour
record for `contracts/escrow/tests/token_conformance.rs`.

The contract claims to work with **any** SEP-41 token, but the rest of the
test suite runs against the Stellar Asset Contract (SAC) and hand-written
mocks. This suite proves the claim the way an integrator meets it: the
full escrow lifecycle runs against every token implementation in
`TokenKind::ALL`, in one parameterised test file.

```bash
cd contracts/escrow
cargo test --test token_conformance
```

CI runs the suite as its own step in the "Soroban contract (test + wasm
build)" job, and it is also included in plain `cargo test`.

## Implementations under test

| Suite variant | What it actually is | Decimals |
|---|---|---|
| `NativeSac` | The built-in SAC for native XLM (`Asset::Native`), deployed in the test environment with `env.deployer().with_stellar_asset(...)`. Balances are classic account balances, so the payer is a funded `G...` account entry. | 7 |
| `IssuedSac` | The built-in SAC for an issuer-administered classic asset created with `register_stellar_asset_contract_v2`. The suite asserts the issuer carries **no flags** — flag behaviour is a separate concern (see "Out of scope"). | 7 |
| `Custom6Decimals` | A test-only SEP-41 contract (`CustomSep41Token`), i.e. a token with arbitrary implementation details and its own storage. Run at 6 decimals, the USDC-shaped precision. | 6 |
| `Custom18Decimals` | The same contract at 18 decimals, to prove nothing in the escrow assumes 7. | 18 |

Why a hand-written custom token instead of OpenZeppelin's `stellar-tokens`:
adding it would put a second token implementation into the audited
dependency graph (`deny.toml`, `docs/supply-chain.md`) for a test-only
fixture. `CustomSep41Token` implements the same SEP-41 surface the SAC
does — `balance`, `transfer`, `transfer_from`, `approve`, `allowance`,
`burn`, `burn_from`, `decimals`, `name`, `symbol`, strict `from`
authorization, allowance accounting, reverts on insufficient balance — and
is called through the SDK's own `token::TokenClient`, so it is exercised
exactly like a third-party token would be.

## Behaviour differences

| Behaviour | Native SAC | Issued-asset SAC (no flags) | Custom SEP-41 (6 dec) | Custom SEP-41 (18 dec) |
|---|---|---|---|---|
| `decimals()` | 7 | 7 | 6 | 18 |
| Admin / mint after deployment | none — native XLM cannot be minted; balances come from classic account entries and protocol payments | the issuer is admin; `mint` requires issuer auth | the fixture's admin; `mint` requires admin auth | same |
| Where balances live | account entries for `G...` addresses; SAC contract data for contract addresses | SAC contract data | the token contract's own storage | same |
| SEP-41 surface used by the escrow | `balance`, `transfer` | same | same | same |
| Transfer authorization | `from` must authorize the transfer | same | same | same |
| Insufficient balance | revert (`Error(Contract, #10)` in the test host) | revert | revert (`TokenError::InsufficientBalance`) | same |
| Rescaling or rounding by the escrow | none — amounts are raw `i128` units | none | none | none |
| Escrow lifecycle results | identical | identical | identical | identical |

Read across the table: the escrow itself sees no difference. Everything
that varies (mint authority, storage location, decimals, the shape of the
revert) is the token implementation's business, which is why the contract
must never interpret token metadata.

## Amounts and decimals

`create_escrow` stores and moves the `amount` exactly as given — raw
units in the token's smallest denomination. The contract never calls
`decimals()`, never rescales, and never rounds. Integrators are
responsible for scaling whole-token amounts by `10^decimals` before
calling, and for displaying returned amounts the same way.

The suite pins that behaviour:

- every variant is created, released, refunded and timeout-refunded with
  the same *whole-token* amounts, scaled by its own `decimals()` — 300
  whole tokens is `3_000_000_000` raw at 7 decimals, `300_000_000` at 6,
  `300_000_000_000_000_000_000` at 18;
- `every_token_reports_the_decimals_in_the_behaviour_table` asserts
  `decimals()` matches this document;
- `six_decimal_amounts_pass_through_unscaled` escrows 1.5 USDC-shaped
  tokens (`1_500_000` raw) and asserts the stored amount and the payout are
  byte-for-byte the same value — an amount that has no whole-stroop
  representation at 7 decimals.

## Lifecycle coverage

Each test below iterates `TokenKind::ALL`, so every lifecycle step is
exercised against every implementation:

| Test | What it pins |
|---|---|
| `create_locks_the_amount_and_records_the_escrow` | payer debited exactly `amount`, escrow holds it, stored record matches, status `Funded` |
| `create_rejects_non_positive_amounts` | zero/negative rejected before any token interaction |
| `create_rejects_a_deadline_that_is_not_strictly_in_the_future` | `InvalidRefundAfter` |
| `create_reverts_when_the_token_cannot_deliver_the_full_amount` | an overdraft reverts, payer untouched, no escrow created |
| `release_pays_the_payee_in_full_and_marks_released` | exact payout, escrow emptied, status `Released` |
| `release_is_restricted_to_the_releaser` | `Unauthorized`, no movement |
| `release_cannot_settle_an_escrow_twice` | `NotFunded`, no double payout |
| `refund_returns_the_amount_to_the_payer_and_marks_refunded` | payer made whole, status `Refunded` |
| `refund_before_the_deadline_is_restricted_to_the_releaser` | `Unauthorized` before the deadline |
| `timeout_refund_lets_a_stranger_return_the_funds_to_the_payer` | timeout refund at the deadline, always to the payer |
| `settled_escrows_reject_the_other_path` | released → no refund, refunded → no release |
| `custom_tokens_implement_the_full_sep41_surface` | custom variants really are SEP-41 (`approve`/`transfer_from`/`burn`) |

## Recommended tokens for integrators

- **USDC on Stellar** — a classic issued asset exposed through its SAC.
  This is the `IssuedSac` variant (7 decimals, issuer flags are the
  issuer's choice; the suite covers the no-flags case). This is the
  recommended production token for escrow amounts.
- **Native XLM** — the `NativeSac` variant. Works the same, with the
  caveat that native balances are classic account balances, and the test
  environment has to seed them explicitly.
- **Any SEP-41 fungible token** that:
  - reverts rather than silently under-delivering on `transfer` (the
    escrow's balance-delta check rejects short delivery with
    `BalanceMismatch`, so a fee-on-transfer token is not supported —
    see `tests/malicious_token.rs`),
  - requires `from` authorization on `transfer` (the escrow relies on
    `payer.require_auth()` plus the token's own check),
  - does not rebase or change balances between transactions (escrow
    amounts are fixed at creation).

OpenZeppelin-style implementations satisfy all three and are represented
here by `CustomSep41Token`. Tokens with a transfer fee, rebasing supply,
or non-SEP-41 transfer semantics are out of scope for escrow use.

## Out of scope

Issuer-flag edge cases — clawback, auth-required, auth-revocable — are
deliberately tested separately from this suite. This document and the
tests are about token *implementations*, not issuer flags.

## Adding another implementation

Add a `TokenKind` variant, its `decimals()`/`label()`, and its
registration/funding in `funded_token`; every lifecycle test in the suite
picks it up automatically. If the implementation introduces a behaviour
difference an integrator could hit, add it to the table above and to the
`every_token_reports_the_decimals_in_the_behaviour_table` assertions.
