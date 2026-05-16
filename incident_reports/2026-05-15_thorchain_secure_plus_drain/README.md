# Incident Report — THORChain Secured-Asset Phantom-Mint Drain

**Date**: 2026-05-15
**Chains**: Bitcoin, Ethereum, BSC, Base (multi-chain, simultaneous)
**Status**: Active during 07:23 – ~10:30 UTC, halted by node operators after detection
**Net loss**: ~$10.8M (3,443 ETH + 36.85 BTC + 96.6 BNB + Base residual)

---

## 1. Actors

| Role | Address | Notes |
|---|---|---|
| Attacker (final consolidation) | [`0xd477b69551f49C0519F9B18c55030676138890Bd`](https://etherscan.io/address/0xd477b69551f49C0519F9B18c55030676138890Bd) | Received 1,866 ETH in single tx after sweep |
| Attacker (mid-consolidation) | [`0x82Fc0d5150F3548027e971eC04c065f3c93154Eb`](https://etherscan.io/address/0x82Fc0d5150F3548027e971eC04c065f3c93154Eb) | Mentioned in ZachXBT alert |
| Attacker (drain recipient) | [`0x82a5CF67F3e6970C0529122178075C0a94878bDA`](https://etherscan.io/address/0x82a5CF67F3e6970C0529122178075C0a94878bDA) | Received 10 of 18 visible Router outbounds (56%); 204 total txs |
| Attacker (deposit source) | [`0xD164BDe670eb5f5d9e34e7258082385fe831a7be`](https://etherscan.io/address/0xD164BDe670eb5f5d9e34e7258082385fe831a7be) | Initiated `depositWithExpiry` calls |
| Attacker THORChain account | `thor19tq5gvcn7uvz0fayyy8cz48hy6773aphl5pxd6` | Mint recipient embedded in memo |
| Bitcoin theft address | `bc1ql4u94klk265lnfur2ujk9p6uh52f2a8jhf6f37` | 36.85 BTC drained |
| THORChain Router (Ethereum) | [`0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146`](https://etherscan.io/address/0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146) | Router v4.1.1 — **contract itself is NOT vulnerable** |
| Sample attacker inbound tx | [`0xd5447901bd917f87a5cb4c1b233029b7d89150595c5c09429db717f5959989ce`](https://etherscan.io/tx/0xd5447901bd917f87a5cb4c1b233029b7d89150595c5c09429db717f5959989ce) | XRUNE deposit with `secure+` memo |

---

## 2. Vulnerability — Secured-Asset Phantom-Mint via Bifrost Filter Bypass

The bug is **not in any Solidity contract**. It is a multi-layer failure across THORChain's off-chain stack (thornode + bifrost), enabling free minting of "Secured Assets" — internal claims on the real Asgard vault — without ever depositing the corresponding L1 asset.

### Root cause (architectural)

The Secured Asset feature lets a user deposit an L1 asset to Asgard with a `SECURE+:thor...` memo and receive a 1:1 share representation on THORChain. The user can later redeem via `SECURE-:0xAddr` to withdraw from Asgard.

**The trust chain has THREE gates, and ALL THREE were open:**

| Gate | Component | Expected behavior | Actual behavior (2026-05-14 commit) |
|---|---|---|---|
| G1 | Bifrost EVM scanner `getTxInFromSmartContract` | Reject Deposit events where event's `vault` parameter is not a known active Asgard | **Only rejects "known vault + wrong router" mismatches; unknown `vault` parameter is silently PASSED through** |
| G2 | thornode `handleObservedTxInQuorum` (`handler_observed_tx_helpers.go:172,234,266`) | Reject if the observed tx's L1 destination is not an active Asgard | **Checks the OBSERVER pubkey (`tx.ObservedPubKey`) via `vault.IsAsgard()` and `vault.Status == InactiveVault`, but NEVER checks the DESTINATION (`tx.Tx.ToAddress`)** — the observer is always a real Asgard since legit Bifrost nodes are reporting; this check is always-true and useless against fake destinations |
| G3 | `SecuredAssetMgr.Deposit` | Reject if source vault is not a real Asgard | Only checks halt / asset-type / pool-exists; **no destination/source vault validation** |

The attacker exploits all three:

1. Call `Router.depositWithExpiry(vault=ATTACKER_OWN_ADDR, asset, amount, "SECURE+:thor...", expiry)` — tokens self-transfer to attacker's own address, NOT to Asgard. Router emits a `Deposit` event.
2. Bifrost scanner sees the event. Since `ATTACKER_OWN_ADDR` is unknown to `pubkeyMgr.IsValidPoolAddress()`, G1 falls through (bug: bypass instead of reject).
3. Bifrost reports the event to thornode. G2 only checks the observer's pubkey is a valid vault — it is, since real Bifrost nodes signed the observation. Destination is not checked.
4. thornode dispatches by memo prefix `SECURE+` to `SecuredAssetMgr.Deposit`, which inflates `pool.Depth` by `amount` (line 100 of `manager_secured_asset_current.go`) **without verifying anything actually landed at a real vault** — phantom liquidity injection.
5. Attacker now holds `amount` of secured-asset shares, fully redeemable against the REAL Asgard.
6. Attacker submits a `MsgDeposit` on THORChain with memo `SECURE-:0xAttackerEthAddr` and `coins: <amount> secured-asset`. thornode schedules an outbound from real Asgard to attacker's Ethereum address.
7. Outbound memo defaults to empty string because protocol-generated redemption outbounds have no inbound `OUT:` reference (`manager_txout_current.go:if toi.Memo == ""` fallback path that explicitly handles "protocol-generated swaps lacking observed transactions").
8. TSS signs, L1 broadcasts, real Asgard loses real funds.

### Why this propagates across 4 chains simultaneously

All chain clients share `bifrost/pkg/chainclients/shared/evm/smartcontract_log_parser.go` and `x/thorchain/manager_secured_asset_current.go`. The bug is in code reused across every supported chain. One discovery → simultaneous multi-chain drain.

### Why the per-call cap forced ~150 iterations over 3 hours

Outbound scheduling enforces a per-block / per-vault maximum (likely a fraction of pool depth). Attacker must iterate. The forced cadence is what gave node operators (SamYap, et al.) a ~3-hour detection window before reaching emergency halt — which preserved ~15-20% of pool reserves.

---

## 3. Cited code (verbatim from develop @ `215cbad`, 2026-05-14 HEAD)

### G3 — `x/thorchain/manager_secured_asset_current.go:72-115`

```go
func (s *SecuredAssetMgr) Deposit(
    ctx cosmos.Context,
    asset common.Asset,
    amount cosmos.Uint,
    owner cosmos.AccAddress,
    assetAddr common.Address,    // ← purported L1 source, NEVER verified
    txID common.TxID,
) (cosmos.Coin, error) {
    if err := s.CheckHalt(ctx); err != nil {
        return cosmos.Coin{}, err
    }
    if asset.IsNative() {
        return cosmos.Coin{}, fmt.Errorf("native assets cannot be deposited")
    }
    asset = asset.GetSecuredAsset()
    pool, shareSupply, err := s.GetSecuredAssetStatus(ctx, asset)
    if err != nil {
        return cosmos.Coin{}, err
    }
    // ============= MISSING VALIDATION =============
    // No check: was `amount` actually deposited to an active Asgard on L1?
    // No check: is `assetAddr` a known/active vault address?
    // No check: does `txID` correspond to a verified inbound consensus?
    // ==============================================
    mintAmt := s.calcMintAmt(shareSupply, pool.Depth, amount)
    coin := common.NewCoin(asset, mintAmt)
    err = s.keeper.MintAndSendToAccount(ctx, owner, coin)    // ← mint to ANY thor addr from memo
    if err != nil {
        return cosmos.Coin{}, err
    }
    pool.Depth = pool.Depth.Add(amount)                      // ← PHANTOM LIQUIDITY
    s.keeper.SetSecuredAsset(ctx, pool)
    // ... event emission ...
}
```

### G1 — `bifrost/pkg/chainclients/ethereum/ethereum_block_scanner.go:730-810`

```go
// Filter only rejects KNOWN-VAULT + WRONG-ROUTER combinations.
// Unknown vault is silently passed through.
ok, cpi := e.pubkeyMgr.IsValidPoolAddress(txInItem.To, common.ETHChain)
if !ok {
    // bypass — continue processing without rejection
} else {
    expectedRouter := e.pubkeyMgr.GetContract(common.ETHChain, cpi.PubKey)
    if expectedRouter != common.NoAddress {
        depositRouter := evm.DepositEventRouter(receipt.Logs)
        if depositRouter != nil &&
            !strings.EqualFold(expectedRouter.String(), depositRouter.String()) {
            return nil  // rejected
        }
    }
}
```

### Decoded attacker inbound tx

```
Function:   Router.depositWithExpiry
vault:      0x82a5CF67F3e6970C0529122178075C0a94878bDA   ← attacker's own address
asset:      0x69fa0feE221AD11012BAb0FdB45d444D3D2Ce71c   (XRUNE Token)
amount:     3,804.45 XRUNE
memo:       "secure+:thor19tq5gvcn7uvz0fayyy8cz48hy6773aphl5pxd6"
                  ↑                 ↑
            SECURE+ prefix     attacker thor mint recipient
expiration: 1748999891
ETH value:  0 ETH
from:       0xD164BDe670eb5f5d9e34e7258082385fe831a7be
to:         0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146   (Router)
```

---

## 4. The Fix (what THORChain should ship)

Three independent fixes, each sufficient on its own; ideally all three:

### F1 — Bifrost: reject unknown-vault Deposit events

```go
// bifrost/pkg/chainclients/ethereum/ethereum_block_scanner.go
ok, cpi := e.pubkeyMgr.IsValidPoolAddress(txInItem.To, common.ETHChain)
if !ok {
    // OLD: bypass
    // NEW:
    return nil  // unknown vault → reject entirely
}
```

### F2 — thornode: verify DESTINATION (not observer) is active vault

Existing checks at `handler_observed_tx_helpers.go:234,266` validate the OBSERVER's pubkey (`tx.ObservedPubKey`), which is always a real Asgard because legit Bifrost nodes are reporting. The check that's missing is on the L1 DESTINATION (`tx.Tx.ToAddress`).

```go
// x/thorchain/handler_observed_tx_helpers.go (handleObservedTxInQuorum, after line 232)
// EXISTING (insufficient):
//   if !vault.IsAsgard() { return nil }                  // observer check
//   if vault.Status == InactiveVault { return nil }      // observer check
//
// ADD (missing):
if !k.IsActiveVaultAddress(ctx, tx.Tx.ToAddress, tx.Tx.Chain) {
    refundTx(ctx, tx, mgr, CodeInvalidVault,
        "observed inbound destination is not an active Asgard", "")
    return nil
}
// Note: IsActiveVaultAddress helper does not yet exist; it must look up active
// asgard vaults for the given chain and compare their derived L1 addresses against
// tx.Tx.ToAddress.
```

### F3 — SecuredAssetMgr.Deposit: defense-in-depth vault check

```go
// x/thorchain/manager_secured_asset_current.go (in Deposit, after existing checks)
// Note: IsActiveVaultAddress also new — same helper as F2.
if !s.keeper.IsActiveVaultAddress(ctx, assetAddr, asset.Chain) {
    return cosmos.Coin{}, fmt.Errorf(
        "secured asset deposit must land on an active vault, got %s on %s",
        assetAddr, asset.Chain)
}
```

**None of these helpers exist in 2026-05-14 codebase** (verified by grep: `IsActiveVault`, `IsActiveVaultAddress`, `GetActiveVault` — no matches). The fix requires both creating the helper and calling it in at least one gate.

---

## 5. Local Reproduction

### Option A — Standalone simulation (Windows native)

```bash
cd incident_reports/2026-05-15_thorchain_secure_plus_drain
go test -v -run TestSecuredAssetPhantomMintDrain
```

`poc_drain_simulation_test.go` in this directory is a minimal in-process reproduction. It mimics `SecuredAssetMgr.Deposit/Withdraw` with the same arithmetic (`calcMintAmt`, `GetSafeShare`-equivalent) and demonstrates the drain mechanism. Runs on any platform with Go 1.21+. **Does NOT use thornode code** — proves the bug *class* is exploitable; not the *instance*.

### Option B — Drop-in thornode unit test (Linux/macOS required)

`poc_thornode_dropin_test.go.txt` (in this directory) is ready to drop into a thornode clone:

```bash
git clone https://gitlab.com/thorchain/thornode.git
cd thornode
git checkout 215cbad           # 2026-05-14, pre-attack vulnerable HEAD
cp .../poc_thornode_dropin_test.go.txt x/thorchain/poc_drain_test.go
go test -v ./x/thorchain -run TestSecuredAssetDrainPoC
```

**Why Linux/macOS only**: thornode depends on `CosmWasm/wasmvm` (uses `unix.Flock`) and `bytedance/sonic` (unsafe Go runtime), both Linux/macOS-only. Cannot build on Windows native.

### Option C — Full mocknet end-to-end

See `make run-mocknet` in the thornode repo. Outside the scope of this report (requires Docker + several GB RAM + multi-hour setup).

---

## 6. References

- thornode repo: [gitlab.com/thorchain/thornode @ 215cbad](https://gitlab.com/thorchain/thornode/-/tree/215cbad) (vulnerable HEAD as of 2026-05-14)
- code-423n4 2024-06 Router audit: [github.com/code-423n4/2024-06-thorchain](https://github.com/code-423n4/2024-06-thorchain)
- 2021 Bifrost vuln (precursor class): [gist HildisviniOttar/7198452b](https://gist.github.com/HildisviniOttar/7198452b312b8b2da9510ad8b7bc75d2)
- Secured Assets dev docs: [dev.thorchain.org/concepts/secured-assets.html](https://dev.thorchain.org/concepts/secured-assets.html)
- CoinDesk coverage: [thorchain halts trading after $10M cross-chain exploit](https://www.coindesk.com/tech/2026/05/15/thorchain-halts-trading-after-usd10-million-cross-chain-exploit-rune-token-drops-12)
- ZachXBT alert: Telegram "Investigations by ZachXBT", 2026-05-15

## 7. Status

| Item | Status |
|---|---|
| SecuredAssetMgr.Deposit lacks defense-in-depth vault check | ✅ confirmed in source — `IsActiveVault*` helper doesn't exist in codebase |
| thornode's own `TestDepositAndWithdraw` exercises vulnerable path | ✅ confirmed at `manager_secured_asset_current_test.go:33-35` |
| Standalone PoC (abstract bug class simulation) | ✅ in this directory, PASS on Windows native |
| Real-thornode PoC artifact | ✅ ready; requires Linux/macOS to run |
| On-chain forensics: 1 attacker tx decoded (`0xd5447901` with `secure+` memo) | ✅ |
| On-chain forensics: 18 outbounds with empty memo confirmed | ✅ |
| **Full attack-chain entry point** | ⚠️ **NOT confirmed** — see § 8 |
| Official post-mortem | ⏳ pending (24-72h after halt) |

## 8. Open question — Where does the attacker's inbound enter?

After deeper inspection of `bifrost/observer/observe.go:638-645`, the generic
Bifrost observer filter **does** reject inbounds whose destination is not a
known active pool address (`IsValidPoolAddress(txInItem.To, chain)`). This
means the attack chain I framed in § 2 — "Router.depositWithExpiry with
`vault = ATTACKER_OWN_ADDR` triggers Bifrost report" — does NOT work against
the actual codebase. Bifrost drops the observation before it reaches thornode.

The architectural bug in `SecuredAssetMgr.Deposit` (no vault attestation
check) is real and demonstrable in isolation (Layer 1 / Layer 2 PoC), but
the production attack must have used a different entry. Candidate entries
still open (no specific evidence for any):

- (a) `0x82a5CF67…` was an active Asgard EOA at 07:23 UTC 5/15 (need
      historical pubkeyMgr snapshot to verify)
- (b) `pubkeyMgr` stale-cache: retired vault address not removed at rotation
- (c) Decoded tx `0xd5447901` is unrelated noise; real attack vector uses
      different memo type (e.g., `add`, refund, migrate)
- (d) TSS / quorum compromise (high cost, low probability)
- (e) A different MsgDeposit path on Thorchain native chain that bypasses
      the filter (e.g., via a sibling module like RUNEPool, TradeAccount,
      or wasm exec)
- (f) Bug in `IsValidPoolAddress` itself

Confidence in full attribution: **~30%** for `secure+` as the vehicle, given
the entry-point filter caught the obvious version. Awaiting official
post-mortem to narrow this down.

## 9. What stays defensible regardless of which vector is true

- The **SecuredAssetMgr.Deposit defense-in-depth gap is real** and would be a
  high-severity finding in any audit even if it wasn't this specific incident's
  vehicle. A handler that mints L1-redeemable shares without verifying the
  L1-side attestation violates the defense-in-depth principle even when an
  upstream filter is correct today.
- The **`IsActiveVault*` helper missing from `x/thorchain/keeper`** is a real
  primitive gap: there's no canonical way for downstream handlers to do
  defense-in-depth even if they wanted to.
- The **on-chain symptom (empty memo on `TransferOut`) genuinely points to
  an internal-protocol-generated outbound path** — secured-asset withdrawal
  is one such path, but so are migrate, yggdrasil return, solvency
  reconciliation, and others.

The standalone simulation PoC demonstrates the bug-class is exploitable
*if reached*; it doesn't demonstrate this is *the* 5/15 mechanism.
