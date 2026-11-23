//! Token conformance suite (issue #133).
//!
//! The contract claims to work with any SEP-41 token, but the rest of the
//! suite runs against the Stellar Asset Contract (SAC) and hand-written
//! mocks. This file proves the claim the way an integrator would experience
//! it: every escrow lifecycle below runs against **all** token
//! implementations in [`TokenKind::ALL`] —
//!
//! - `NativeSac`: the built-in SAC for native XLM (7 decimals, no admin,
//!   balances are classic account balances),
//! - `IssuedSac`: the built-in SAC for an issuer-administered classic asset
//!   with no issuer flags set (7 decimals),
//! - `Custom6Decimals` / `Custom18Decimals`: a test-only SEP-41 contract
//!   (see [`CustomSep41Token`]) run at 6 and 18 decimals, i.e. amounts whose
//!   precision differs from Stellar's own 7.
//!
//! Per-token behaviour differences, how amounts are scaled, and the tokens
//! recommended for integrators are documented in `docs/token-conformance.md`
//! and asserted here (decimals, no issuer flags, full SEP-41 surface).
//!
//! Deliberately **not** covered here: issuer-flag behaviour (clawback, auth
//! required) — that is `tests/malicious_token.rs`'s territory. This file is
//! about token *implementations*, not flags.

use docforum_escrow::{Error, EscrowContract, EscrowContractClient, EscrowStatus};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    testutils::{Address as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    xdr::{
        AccountEntry, AccountEntryExt, AccountId, Asset, LedgerEntry, LedgerEntryData,
        LedgerEntryExt, LedgerKey, LedgerKeyAccount, Limited, Limits, PublicKey, ScAddress,
        SequenceNumber, Thresholds, Uint256, VecM, WriteXdr,
    },
    Address, Bytes, Env, String, TryIntoVal,
};
use std::rc::Rc;

// --- token implementations under test ---

/// One variant per token implementation the escrow must support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    NativeSac,
    IssuedSac,
    Custom6Decimals,
    Custom18Decimals,
}

impl TokenKind {
    /// Every lifecycle test iterates this list; a new token implementation
    /// added here is picked up by all of them.
    const ALL: [Self; 4] = [
        Self::NativeSac,
        Self::IssuedSac,
        Self::Custom6Decimals,
        Self::Custom18Decimals,
    ];

    /// The value asserted against `decimals()` and used to scale whole-token
    /// amounts into raw units.
    fn decimals(self) -> u32 {
        match self {
            Self::NativeSac | Self::IssuedSac => 7,
            Self::Custom6Decimals => 6,
            Self::Custom18Decimals => 18,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NativeSac => "native SAC",
            Self::IssuedSac => "issued-asset SAC (no flags)",
            Self::Custom6Decimals => "custom SEP-41 (6 decimals)",
            Self::Custom18Decimals => "custom SEP-41 (18 decimals)",
        }
    }

    fn is_custom(self) -> bool {
        matches!(self, Self::Custom6Decimals | Self::Custom18Decimals)
    }
}

/// `whole` whole tokens expressed in the token's smallest unit.
///
/// The escrow contract is decimal-agnostic: it stores and moves raw `i128`
/// amounts and never rescales them. Integrators are responsible for scaling,
/// which is exactly what this helper does in the tests.
fn units(kind: TokenKind, whole: i128) -> i128 {
    whole * 10_i128.pow(kind.decimals())
}

// --- native SAC ---

/// Deterministic ed25519 key for the native payer. Native XLM lives in
/// classic account entries, so the native variant needs a real account
/// rather than the contract addresses `Address::generate` produces.
const NATIVE_PAYER_KEY: [u8; 32] = [7; 32];

fn account_address(env: &Env, key: [u8; 32]) -> (Address, AccountId) {
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key)));
    let address: Address = ScAddress::Account(account_id.clone())
        .try_into_val(env)
        .unwrap();
    (address, account_id)
}

/// Writes the classic account entry a native-XLM holder needs. On a real
/// network the account exists because someone funded it; in the test
/// environment the ledger starts empty, so the suite creates it explicitly.
fn seed_account(env: &Env, key: [u8; 32], stroops: i64) -> Address {
    let (address, account_id) = account_address(env, key);
    let entry = LedgerEntry {
        last_modified_ledger_seq: 0,
        data: LedgerEntryData::Account(AccountEntry {
            account_id: account_id.clone(),
            balance: stroops,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: SequenceNumber(0),
            thresholds: Thresholds([1; 4]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    };
    let ledger_key = LedgerKey::Account(LedgerKeyAccount { account_id });
    env.host()
        .add_ledger_entry(&Rc::new(ledger_key), &Rc::new(entry), None)
        .unwrap();
    address
}

fn asset_bytes(env: &Env, asset: &Asset) -> Bytes {
    let mut buf = Limited::new(Vec::new(), Limits::none());
    asset.write_xdr(&mut buf).unwrap();
    Bytes::from_slice(env, &buf.inner)
}

fn deploy_native_sac(env: &Env) -> Address {
    env.deployer()
        .with_stellar_asset(asset_bytes(env, &Asset::Native))
        .deploy()
}

// --- custom SEP-41 token (test-only implementation) ---

#[contracttype]
#[derive(Clone)]
enum TokenKey {
    Admin,
    Decimals,
    Name,
    Symbol,
    Balance(Address),
    Allowance(Address, Address),
}

#[contracttype]
#[derive(Clone)]
struct AllowanceValue {
    amount: i128,
    live_until_ledger: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TokenError {
    InsufficientBalance = 1,
    InsufficientAllowance = 2,
    NotInitialised = 3,
}

fn read_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&TokenKey::Admin)
        .unwrap_or_else(|| panic!("{}", TokenError::NotInitialised as u32))
}

fn read_balance(env: &Env, id: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&TokenKey::Balance(id.clone()))
        .unwrap_or(0)
}

fn write_balance(env: &Env, id: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&TokenKey::Balance(id.clone()), &amount);
}

fn receive(env: &Env, to: &Address, amount: i128) -> Result<(), TokenError> {
    let balance = read_balance(env, to);
    let Some(new_balance) = balance.checked_add(amount) else {
        return Err(TokenError::InsufficientBalance);
    };
    write_balance(env, to, new_balance);
    Ok(())
}

fn spend(env: &Env, from: &Address, amount: i128) -> Result<(), TokenError> {
    let balance = read_balance(env, from);
    if balance < amount {
        return Err(TokenError::InsufficientBalance);
    }
    write_balance(env, from, balance - amount);
    Ok(())
}

fn read_allowance(env: &Env, from: &Address, spender: &Address) -> i128 {
    let key = TokenKey::Allowance(from.clone(), spender.clone());
    match env.storage().persistent().get::<_, AllowanceValue>(&key) {
        Some(allowance) if allowance.live_until_ledger >= env.ledger().sequence() => {
            allowance.amount
        }
        Some(_) | None => 0,
    }
}

fn write_allowance(env: &Env, from: &Address, spender: &Address, amount: i128, live_until: u32) {
    let key = TokenKey::Allowance(from.clone(), spender.clone());
    if amount == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(
            &key,
            &AllowanceValue {
                amount,
                live_until_ledger: live_until,
            },
        );
    }
}

/// Minimal, spec-shaped SEP-41 fungible token.
///
/// Not OpenZeppelin's implementation: pulling `stellar-tokens` in would add a
/// second token implementation to the audited dependency graph for a test-only
/// fixture. What matters for conformance is that the escrow sees a contract
/// that implements the same SEP-41 surface as the SAC — including strict
/// `from` authorization, allowance accounting, and reverts on insufficient
/// balance — but keeps its balances in its own storage at an arbitrary
/// `decimals`, which the built-in SAC cannot do.
#[contract]
pub struct CustomSep41Token;

#[contractimpl]
impl CustomSep41Token {
    /// # Panics
    ///
    /// Panics if the token is registered twice, which the test suite never
    /// does.
    pub fn __constructor(env: Env, admin: Address, decimals: u32, name: String, symbol: String) {
        env.storage().instance().set(&TokenKey::Admin, &admin);
        env.storage().instance().set(&TokenKey::Decimals, &decimals);
        env.storage().instance().set(&TokenKey::Name, &name);
        env.storage().instance().set(&TokenKey::Symbol, &symbol);
    }

    /// # Errors
    ///
    /// - [`TokenError::InsufficientBalance`] if the balance would overflow.
    pub fn mint(env: Env, to: Address, amount: i128) -> Result<(), TokenError> {
        read_admin(&env).require_auth();
        receive(&env, &to, amount)
    }

    /// # Errors
    ///
    /// - [`TokenError::InsufficientBalance`] if `from` holds less than
    ///   `amount`.
    pub fn burn(env: Env, from: Address, amount: i128) -> Result<(), TokenError> {
        from.require_auth();
        spend(&env, &from, amount)
    }

    /// # Errors
    ///
    /// - [`TokenError::InsufficientAllowance`] if `spender` has no allowance
    ///   for `from` covering `amount`.
    /// - [`TokenError::InsufficientBalance`] if `from` holds less than
    ///   `amount`.
    pub fn burn_from(
        env: Env,
        spender: Address,
        from: Address,
        amount: i128,
    ) -> Result<(), TokenError> {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount)?;
        spend(&env, &from, amount)
    }

    /// # Errors
    ///
    /// - [`TokenError::InsufficientBalance`] if `from` holds less than
    ///   `amount`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), TokenError> {
        from.require_auth();
        spend(&env, &from, amount)?;
        receive(&env, &to, amount)
    }

    /// # Errors
    ///
    /// - [`TokenError::InsufficientAllowance`] if `spender` has no allowance
    ///   for `from` covering `amount`.
    /// - [`TokenError::InsufficientBalance`] if `from` holds less than
    ///   `amount`.
    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), TokenError> {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount)?;
        spend(&env, &from, amount)?;
        receive(&env, &to, amount)
    }

    /// # Errors
    ///
    /// Never returns an error today; the `Result` matches the SEP-41 shape.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "SEP-41's approve returns Result in third-party implementations; keep the shape so callers match"
    )]
    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        live_until_ledger: u32,
    ) -> Result<(), TokenError> {
        from.require_auth();
        write_allowance(&env, &from, &spender, amount, live_until_ledger);
        Ok(())
    }

    #[must_use]
    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        read_allowance(&env, &from, &spender)
    }

    #[must_use]
    pub fn balance(env: Env, id: Address) -> i128 {
        read_balance(&env, &id)
    }

    /// # Panics
    ///
    /// Panics if the token was not constructed, which the suite never does.
    #[must_use]
    pub fn decimals(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&TokenKey::Decimals)
            .expect("token not initialised")
    }

    /// # Panics
    ///
    /// Panics if the token was not constructed, which the suite never does.
    #[must_use]
    pub fn name(env: Env) -> String {
        env.storage()
            .instance()
            .get(&TokenKey::Name)
            .expect("token not initialised")
    }

    /// # Panics
    ///
    /// Panics if the token was not constructed, which the suite never does.
    #[must_use]
    pub fn symbol(env: Env) -> String {
        env.storage()
            .instance()
            .get(&TokenKey::Symbol)
            .expect("token not initialised")
    }
}

fn spend_allowance(
    env: &Env,
    from: &Address,
    spender: &Address,
    amount: i128,
) -> Result<(), TokenError> {
    let allowance = read_allowance(env, from, spender);
    if allowance < amount {
        return Err(TokenError::InsufficientAllowance);
    }
    let remaining = allowance - amount;
    let key = TokenKey::Allowance(from.clone(), spender.clone());
    let live_until = match env.storage().persistent().get::<_, AllowanceValue>(&key) {
        Some(value) => value.live_until_ledger,
        None => env.ledger().sequence(),
    };
    write_allowance(env, from, spender, remaining, live_until);
    Ok(())
}

// --- harness ---

/// Whole tokens minted to the payer before each test.
const FUNDED_WHOLE_TOKENS: i128 = 1_000;
/// Whole tokens locked in the escrow by each test.
const ESCROW_WHOLE_TOKENS: i128 = 300;
/// Ledger close time at escrow creation.
const CREATED_AT: u64 = 1_000;
/// The escrow's timeout deadline — always strictly after `CREATED_AT`.
const DEADLINE: u64 = 1_100;

struct Fixture<'a> {
    escrow: EscrowContractClient<'a>,
    token: TokenClient<'a>,
    token_id: Address,
    escrow_contract: Address,
    payer: Address,
    payee: Address,
    releaser: Address,
    amount: i128,
    minted: i128,
}

impl Fixture<'_> {
    fn create(&self, env: &Env) -> u64 {
        self.escrow.create_escrow(
            &self.payer,
            &self.payee,
            &self.token_id,
            &self.amount,
            &String::from_str(env, "opaque-condition-ref"),
            &self.releaser,
            &None,
        )
    }

    fn create_with_deadline(&self, env: &Env, deadline: u64) -> u64 {
        self.escrow.create_escrow(
            &self.payer,
            &self.payee,
            &self.token_id,
            &self.amount,
            &String::from_str(env, "opaque-condition-ref"),
            &self.releaser,
            &Some(deadline),
        )
    }

    fn balance(&self, id: &Address) -> i128 {
        self.token.balance(id)
    }
}

/// Deploys the token implementation under test and returns its address plus a
/// payer funded with [`FUNDED_WHOLE_TOKENS`].
fn funded_token(env: &Env, kind: TokenKind, minted: i128) -> (Address, Address) {
    match kind {
        TokenKind::NativeSac => {
            let token_id = deploy_native_sac(env);
            let stroops = i64::try_from(minted).expect("native amounts fit i64 stroops");
            let payer = seed_account(env, NATIVE_PAYER_KEY, stroops);
            (token_id, payer)
        }
        TokenKind::IssuedSac => {
            let issued = env.register_stellar_asset_contract_v2(Address::generate(env));
            assert_eq!(
                issued.issuer().flags(),
                0,
                "the issued-asset SAC under test must carry no issuer flags"
            );
            let payer = Address::generate(env);
            StellarAssetClient::new(env, &issued.address()).mint(&payer, &minted);
            (issued.address(), payer)
        }
        TokenKind::Custom6Decimals | TokenKind::Custom18Decimals => {
            let admin = Address::generate(env);
            let token_id = env.register(
                CustomSep41Token,
                (
                    admin,
                    kind.decimals(),
                    String::from_str(env, "Conformance Token"),
                    String::from_str(env, "CONF"),
                ),
            );
            let payer = Address::generate(env);
            CustomSep41TokenClient::new(env, &token_id).mint(&payer, &minted);
            (token_id, payer)
        }
    }
}

fn fixture<'a>(env: &'a Env, kind: TokenKind) -> Fixture<'a> {
    let minted = units(kind, FUNDED_WHOLE_TOKENS);
    let amount = units(kind, ESCROW_WHOLE_TOKENS);
    let (token_id, payer) = funded_token(env, kind, minted);
    let escrow_contract = env.register(EscrowContract, ());
    Fixture {
        escrow: EscrowContractClient::new(env, &escrow_contract),
        token: TokenClient::new(env, &token_id),
        token_id,
        escrow_contract,
        payer,
        payee: Address::generate(env),
        releaser: Address::generate(env),
        amount,
        minted,
    }
}

// --- lifecycle: create ---

#[test]
fn create_locks_the_amount_and_records_the_escrow() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create(&env);

        assert_eq!(id, 0, "{}: first escrow id", kind.label());
        assert_eq!(
            f.balance(&f.payer),
            f.minted - f.amount,
            "{}: payer debited exactly the escrowed amount",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.escrow_contract),
            f.amount,
            "{}: escrow contract holds the amount",
            kind.label()
        );

        let data = f.escrow.get_escrow(&id);
        assert_eq!(data.payer, f.payer, "{}: stored payer", kind.label());
        assert_eq!(data.payee, f.payee, "{}: stored payee", kind.label());
        assert_eq!(data.token, f.token_id, "{}: stored token", kind.label());
        assert_eq!(
            data.amount,
            f.amount,
            "{}: amount stored in raw units, never rescaled",
            kind.label()
        );
        assert_eq!(data.status, EscrowStatus::Funded, "{}", kind.label());
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Funded,
            "{}: status after create",
            kind.label()
        );
    }
}

#[test]
fn create_rejects_non_positive_amounts() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);

        for amount in [0_i128, -1_i128] {
            let result = f.escrow.try_create_escrow(
                &f.payer,
                &f.payee,
                &f.token_id,
                &amount,
                &String::from_str(&env, "opaque-condition-ref"),
                &f.releaser,
                &None,
            );
            assert_eq!(
                result,
                Err(Ok(Error::InvalidAmount)),
                "{}: amount {amount} rejected",
                kind.label()
            );
        }

        assert_eq!(f.balance(&f.payer), f.minted, "{}", kind.label());
        assert_eq!(f.balance(&f.escrow_contract), 0, "{}", kind.label());
        assert!(
            f.escrow.try_get_status(&0).is_err(),
            "{}: no escrow was created",
            kind.label()
        );
    }
}

#[test]
fn create_rejects_a_deadline_that_is_not_strictly_in_the_future() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        env.ledger().set_timestamp(CREATED_AT);

        for deadline in [CREATED_AT, CREATED_AT - 1] {
            let result = f.escrow.try_create_escrow(
                &f.payer,
                &f.payee,
                &f.token_id,
                &f.amount,
                &String::from_str(&env, "opaque-condition-ref"),
                &f.releaser,
                &Some(deadline),
            );
            assert_eq!(
                result,
                Err(Ok(Error::InvalidRefundAfter)),
                "{}: deadline {deadline} rejected",
                kind.label()
            );
        }

        assert_eq!(f.balance(&f.payer), f.minted, "{}", kind.label());
    }
}

#[test]
fn create_reverts_when_the_token_cannot_deliver_the_full_amount() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let overdraft = f.minted + 1;

        let result = f.escrow.try_create_escrow(
            &f.payer,
            &f.payee,
            &f.token_id,
            &overdraft,
            &String::from_str(&env, "opaque-condition-ref"),
            &f.releaser,
            &None,
        );

        // Each implementation shapes its own revert (the SAC's error differs
        // from the custom token's), so the suite asserts the escrow-facing
        // contract instead: the call fails and nothing is escrowed.
        assert!(result.is_err(), "{}: overdraft rejected", kind.label());
        assert_eq!(
            f.balance(&f.payer),
            f.minted,
            "{}: payer untouched",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.escrow_contract),
            0,
            "{}: nothing escrowed",
            kind.label()
        );
        assert!(
            f.escrow.try_get_status(&0).is_err(),
            "{}: no escrow was created",
            kind.label()
        );
    }
}

// --- lifecycle: release ---

#[test]
fn release_pays_the_payee_in_full_and_marks_released() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create(&env);

        f.escrow.release(&id, &f.releaser);

        assert_eq!(
            f.balance(&f.payee),
            f.amount,
            "{}: payee receives exactly the amount",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.escrow_contract),
            0,
            "{}: escrow is empty after release",
            kind.label()
        );
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Released,
            "{}",
            kind.label()
        );
    }
}

#[test]
fn release_is_restricted_to_the_releaser() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create(&env);
        let stranger = Address::generate(&env);

        let result = f.escrow.try_release(&id, &stranger);

        assert_eq!(
            result,
            Err(Ok(Error::Unauthorized)),
            "{}: stranger rejected",
            kind.label()
        );
        assert_eq!(f.balance(&f.payee), 0, "{}", kind.label());
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Funded,
            "{}: still funded",
            kind.label()
        );
    }
}

#[test]
fn release_cannot_settle_an_escrow_twice() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create(&env);
        f.escrow.release(&id, &f.releaser);

        let second = f.escrow.try_release(&id, &f.releaser);

        assert_eq!(
            second,
            Err(Ok(Error::NotFunded)),
            "{}: double release rejected",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.payee),
            f.amount,
            "{}: no second payout",
            kind.label()
        );
    }
}

// --- lifecycle: refund ---

#[test]
fn refund_returns_the_amount_to_the_payer_and_marks_refunded() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create(&env);

        f.escrow.refund(&id, &f.releaser);

        assert_eq!(
            f.balance(&f.payer),
            f.minted,
            "{}: payer made whole",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.escrow_contract),
            0,
            "{}: escrow is empty after refund",
            kind.label()
        );
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Refunded,
            "{}",
            kind.label()
        );
    }
}

#[test]
fn refund_before_the_deadline_is_restricted_to_the_releaser() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        let id = f.create_with_deadline(&env, DEADLINE);
        let stranger = Address::generate(&env);

        env.ledger().set_timestamp(DEADLINE - 1);
        let result = f.escrow.try_refund(&id, &stranger);

        assert_eq!(
            result,
            Err(Ok(Error::Unauthorized)),
            "{}: stranger rejected before the deadline",
            kind.label()
        );
        assert_eq!(f.balance(&f.payer), f.minted - f.amount, "{}", kind.label());
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Funded,
            "{}",
            kind.label()
        );
    }
}

#[test]
fn timeout_refund_lets_a_stranger_return_the_funds_to_the_payer() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);
        env.ledger().set_timestamp(CREATED_AT);
        let id = f.create_with_deadline(&env, DEADLINE);
        let stranger = Address::generate(&env);

        env.ledger().set_timestamp(DEADLINE);
        f.escrow.refund(&id, &stranger);

        assert_eq!(
            f.balance(&f.payer),
            f.minted,
            "{}: funds go back to the payer, never the caller",
            kind.label()
        );
        assert_eq!(
            f.balance(&stranger),
            0,
            "{}: caller is not paid",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.payee),
            0,
            "{}: payee is not paid",
            kind.label()
        );
        assert_eq!(
            f.escrow.get_status(&id),
            EscrowStatus::Refunded,
            "{}",
            kind.label()
        );

        // Reset the clock so the next kind starts from a clean ledger.
        env.ledger().set_timestamp(0);
    }
}

#[test]
fn settled_escrows_reject_the_other_path() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        // One fixture per kind: the native SAC's contract id is derived from
        // the asset, so a second fixture would try to redeploy it.
        let f = fixture(&env, kind);

        let released_id = f.create(&env);
        f.escrow.release(&released_id, &f.releaser);
        assert_eq!(
            f.escrow.try_refund(&released_id, &f.releaser),
            Err(Ok(Error::NotFunded)),
            "{}: cannot refund a released escrow",
            kind.label()
        );

        let refunded_id = f.create(&env);
        f.escrow.refund(&refunded_id, &f.releaser);
        assert_eq!(
            f.escrow.try_release(&refunded_id, &f.releaser),
            Err(Ok(Error::NotFunded)),
            "{}: cannot release a refunded escrow",
            kind.label()
        );
        assert_eq!(
            f.balance(&f.payee),
            f.amount,
            "{}: only the released escrow paid out",
            kind.label()
        );
    }
}

// --- token-level conformance ---

#[test]
fn every_token_reports_the_decimals_in_the_behaviour_table() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL {
        let f = fixture(&env, kind);

        assert_eq!(
            f.token.decimals(),
            kind.decimals(),
            "{}: decimals() must match docs/token-conformance.md",
            kind.label()
        );
        assert!(!f.token.name().is_empty(), "{}", kind.label());
        assert!(!f.token.symbol().is_empty(), "{}", kind.label());
    }
}

#[test]
fn six_decimal_amounts_pass_through_unscaled() {
    let env = Env::default();
    env.mock_all_auths();

    // 1.5 tokens at 6 decimals — not representable as a whole number of
    // 7-decimal stroops, which is the point: the escrow must neither round
    // nor rescale it.
    let kind = TokenKind::Custom6Decimals;
    let f = fixture(&env, kind);
    let amount = 1_500_000;

    let id = f.escrow.create_escrow(
        &f.payer,
        &f.payee,
        &f.token_id,
        &amount,
        &String::from_str(&env, "opaque-condition-ref"),
        &f.releaser,
        &None,
    );

    assert_eq!(f.escrow.get_escrow(&id).amount, amount, "{}", kind.label());
    f.escrow.release(&id, &f.releaser);
    assert_eq!(f.balance(&f.payee), amount, "{}", kind.label());
    assert_eq!(f.balance(&f.payer), f.minted - amount, "{}", kind.label());
}

#[test]
fn custom_tokens_implement_the_full_sep41_surface() {
    let env = Env::default();
    env.mock_all_auths();

    for kind in TokenKind::ALL.into_iter().filter(|k| k.is_custom()) {
        let f = fixture(&env, kind);
        let spender = Address::generate(&env);
        let amount = units(kind, 10);
        let live_until = env.ledger().sequence() + 100;

        f.token.approve(&f.payer, &spender, &amount, &live_until);
        assert_eq!(
            f.token.allowance(&f.payer, &spender),
            amount,
            "{}: approve is visible via allowance()",
            kind.label()
        );

        f.token.transfer_from(&spender, &f.payer, &f.payee, &amount);
        assert_eq!(f.balance(&f.payee), amount, "{}", kind.label());
        assert_eq!(
            f.token.allowance(&f.payer, &spender),
            0,
            "{}: transfer_from consumes the allowance",
            kind.label()
        );

        f.token.burn(&f.payee, &amount);
        assert_eq!(f.balance(&f.payee), 0, "{}: burn works", kind.label());
    }
}
