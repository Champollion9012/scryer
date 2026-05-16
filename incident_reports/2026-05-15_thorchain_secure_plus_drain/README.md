# Incident Report — THORChain 2026-05-15 Multi-Chain Drain

**Date**: 2026-05-15
**Chains**: Bitcoin, Ethereum, BSC, Base (multi-chain, simultaneous)
**Status**: Active during 07:23 – ~10:30 UTC, halted by node operators after detection
**Net loss**: ~$10.8M (3,443 ETH + 36.85 BTC + 96.6 BNB + Base residual)

> ## ⚠️ Status Update (2026-05-16 from THORChain team)
>
> **Official root cause (preliminary)**: **GG20 TSS (Threshold Signature Scheme) implementation vulnerability**. Vault participants' sensitive key material leaks over time during signing rounds. A new malicious node operator (`thor16ucjv…`) bonded to the network, participated as a TSS member, collected leaked share material across multiple rounds, eventually **reconstructed the vault's full private key**, and signed unauthorised outbound transactions directly across all four chains.
>
> ### Implications for this report
>
> The hypothesis chain in § 2 (Secured-Asset Phantom-Mint via Bifrost Filter Bypass) — and the alternative entry vectors enumerated in § 8 — are **REFUTED** as production attack vectors. The attacker did not need ANY application-layer bypass: with the full TSS private key, they can sign outbounds unilaterally, which explains every observed on-chain symptom (empty memos, single recipient, diverse asset sweep across 19 tokens, cross-chain simultaneity, 7,000× amplification).
>
> ### What stays valid in this report
>
> - § 7.5 on-chain forensics (the 22-tx empty-memo sweep pattern is correctly documented)
> - § 9 defense-in-depth finding on `SecuredAssetMgr.Deposit` — **still a legitimate audit issue**, unrelated to 5/15
> - The standalone PoC in this directory demonstrates the abstract bug class on `SecuredAssetMgr`, not the 5/15 mechanism
>
> See § 10 below for the proper root cause framing and § 11 for the verification plan ("did the team get it right?").

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

## 2. Vulnerability — Secured-Asset Phantom-Mint via Bifrost Filter Bypass  ⚠️ [REFUTED]

> **This entire section is preserved as a record of the initial hypothesis. The official post-mortem (§ 10) attributes the attack to a GG20 TSS share-leakage vulnerability, NOT to any secured-asset phantom-mint. Reader should treat § 2-§ 8 below as historical reasoning that turned out to be wrong, not as the actual 5/15 root cause.**

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

## 7.5. On-chain forensics update (2026-05-16, via Etherscan API V2 batch)

After batch-decoding all txs to/from the Router in block range 25099000-25101000 (the attack window, 07:23-10:30 UTC May 15):

| Metric | Value |
|---|---|
| TransferOut calls from Router | 25 |
| → to attacker `0x82Fc0d5150...` with **empty memo** | **22** |
| → legitimate user swap completions (proper `OUT:<hash>` memos) | 3 |
| depositWithExpiry calls into Router | **2 only** |
| → swap memo to LTC, 0.00196 ETH (~$4.50) | 1 |
| → `secure+:thor19...` memo, 3,804 XRUNE (~$1,140) | 1 |
| Total ETH-side attacker INPUT | **~$1,144** |
| Total ETH-side attacker OUTPUT | **~$8M** (stables + WBTC + XRUNE + CRV + ...) |
| Effective amplification | **~7,000×** |

**Empty-memo outbound asset diversity**: USDC, USDT, WBTC, XRUNE, CRV, DAI, LINK, AAVE, SNX, LUSD, GUSD, USDP, THORSwap, THR_old, LOOM, GRT, DPI, YFI, wstETH (~19 distinct assets all swept to one attacker address).

### Implication

The "redeem 1:1 your phantom shares" framing in § 2 cannot explain a 7,000× amplification on ETH side with only 2 small inbound deposits. The 22 outbounds are not the output of `secure+ → SECURE-` round-trips. The pattern (**single recipient + empty memo + diverse asset sweep**) matches a **vault-rotation / migrate-style sweep** more than a per-tx secured-asset redemption — except `MIGRATE:<height>` would normally have a non-empty memo.

The attack must originate from one of:

- (i) A different inbound chain (BTC most likely — attacker has confirmed BTC address; thornode generates ETH outbounds as cross-chain swap fulfilment)
- (ii) Thorchain-native `MsgDeposit` with internal logic that emits asset moves
- (iii) An **internal thornode trigger** (a bug-injected migration / rescue / consolidation path that defaults memo to empty when the height/identifier is zero)

(iii) is the most parsimonious given the on-chain symptom (empty memo across 22 distinct asset transfers to one address — looks like a single buggy operation enumerating all vault holdings and emitting per-asset transferOut calls).

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
  an internal-protocol-generated outbound path** — but the actual 5/15
  reason is **the attacker holding the vault key and signing outbounds
  directly** (no thornode involvement → no memo generation), not a buggy
  internal handler.

The standalone simulation PoC demonstrates the bug-class is exploitable
*if reached*; it doesn't demonstrate this is *the* 5/15 mechanism.

---

## 10. Official root cause — GG20 TSS share leakage

Per the THORChain team update on 2026-05-16:

### Attack mechanism (official explanation)

1. **Attacker bonded a new node** `thor16ucjv…` to the THORChain network.
   The Ethereum address used to acquire/stake the RUNE bond is linked to
   addresses that later received the stolen funds — strongly indicating a
   single malicious actor.
2. The new node joined the active validator set and **participated as a
   member of the TSS signing committee** for Asgard vaults.
3. THORChain uses **GG20** (Gennaro-Goldfeder 2020) for threshold ECDSA
   signing. The team's investigation indicates the implementation has a
   flaw that causes **vault participants' sensitive key material to leak
   over time** — i.e. each signing round produces protocol messages that
   contain extractable side information about other participants' shares.
4. After accumulating enough leaked material across many signing rounds,
   the attacker **reconstructed the vault's full private key**.
5. With the full ECDSA private key, the attacker signed outbound
   transactions **unilaterally** — bypassing thornode's outbound scheduling,
   memo generation, and quorum entirely. This explains:
    - Empty memos: thornode never produced these outbounds, so no
      `OUT:<inbound>`/`MIGRATE:<height>`/etc. memo was attached
    - Single recipient: the attacker chose where to send, and chose one
      consolidation address per chain
    - Asset diversity (19 tokens swept on ETH): with the private key, the
      attacker drained the vault's full ERC-20 holdings in one sweep, one
      `Router.transferOut` per asset
    - Cross-chain simultaneity: the same TSS key share material derives
      addresses on every supported chain via standard ECDSA → address rules

### Why this slipped past my earlier analysis

I dismissed "TSS / quorum compromise" in § 8 candidate (d) as "high cost,
low probability — needs ≥⅓ node compromise". I assumed TSS compromise
meant compromising a supermajority of nodes. **GG20 has a known class
of attacks where a SINGLE malicious participant can exfiltrate share
information from honest participants' protocol messages over many
signing rounds** — see Lindell et al. (2019, 2020) and Castagnos et al.
on GG18/GG20 leakage. The economic logic also favoured the attacker:
bonding one node costs O(low six figures) of RUNE; if successful, the
payoff is the entire vault contents (O($10M+)).

The empty-memo + diverse-asset + single-recipient symptom should have
immediately suggested "vault key control" instead of "thornode handler
bug". I over-engineered a hypothesis that fit the visible Solidity/Go
surface area without seriously considering the cryptographic layer.

### Network status (per official update)

| Item | Status |
|---|---|
| Network pause | Active; will auto-release in ~12h |
| RUNE transfers + chain observation | To resume after auto-release |
| Trading / signing / LP operations | Remain frozen until fix |
| Loss handling options | Slashing affected nodes; POL absorption; community proposal |

---

## 11. Verification plan — is the official root cause complete?

The team's statement is a **status update**, not a full forensic post-mortem.
"Leading theory" / "indicates" / "preliminary" language suggests they are
not yet 100% certain. Possible refinements / counter-hypotheses to verify:

### Open questions

1. **Is GG20 specifically the buggy primitive**, or is the leak in a
   non-GG20 part of the signing flow (e.g. share resharing / re-randomisation
   / blame protocol)?
2. **Is `thor16ucjv…` really the *only* attacker node**, or did multiple
   nodes coordinate? (Single-node GG20 leak attacks usually need MANY
   signing rounds; if the bond is too recent, the timeline doesn't fit.)
3. **How long was the attacker bonded?** If bonded just days before 5/15,
   the "leak over time" model needs the leak rate to be high enough to
   extract a 256-bit key from N rounds.
4. **Which exact GG20 library version** is thornode using? If it's a known
   academic-flagged version, we can cite the specific CVE / paper. If it's
   custom or modified, the vector may not match published GG20 issues.
5. **Why did THORChain still use the vulnerable variant** when newer
   protocols (CGGMP, FROST, DKLs23) have been available since 2023?
6. **Could the "leakage over time" framing be a face-saving narrative**
   for what's actually a simpler bug (e.g. key share material accidentally
   logged or persisted)? The team may prefer a "subtle cryptographic flaw"
   explanation over "we leaked the share to disk in plain text".

### Concrete verification steps (executable from here)

| # | Step | Tool / source | What it tells us |
|---|---|---|---|
| V1 | Lookup full address `thor16ucjv…` on Thorchain REST API | `thornode/v1/nodes/{addr}` | Bond timestamp, RUNE amount, slash-point history, sign history |
| V2 | Get exact GG20 lib version in thornode's `go.mod` | `cat /c/tmp/poc/thornode/go.mod \| grep -i tss` | Identifies the specific implementation |
| V3 | Diff thornode TSS-related code 2026-04-01 → 2026-05-14 | `git log -p bifrost/tss/` | Find any recent changes to keygen / sign |
| V4 | Cross-reference TSS lib version with known CVEs | scholar / GH security advisories | Confirms which vuln class |
| V5 | Lookup the actual 5/15 outbound tx signatures on-chain | Etherscan / Btcscan | Compare signing key recovery hashes against active vault pubkeys |
| V6 | Query Thorchain explorer for the 5/15 active Asgard members | `/v1/vaults/asgard` archive | See whether attacker node was IN the signing set during attack window |
| V7 | Check pre-attack node bond activity | Thorchain explorer | If a small bond increase happened ~weeks before 5/15, consistent. If days before, harder to reconcile with "leak over time" |
| V8 | Read official post-mortem (when released, 2-7 days out) | Medium / blog | Definitive answer |

### Acceptance criteria for each hypothesis

| Hypothesis | Confirm if | Refute if |
|---|---|---|
| Official: GG20 leakage by single node | V1 shows `thor16ucjv` bonded ≥ N weeks before 5/15 AND V2-V4 identify a matching known vuln AND V6 shows the node was in the active signing set | V1 shows bond < few days OR V6 shows node not in signing set OR V2 shows a TSS variant with no known leak |
| Alt: multiple-node collusion | V1 + V6 show ≥ 2 nodes bonded together with linked funding | V1 shows single bond, V6 single signer |
| Alt: simpler ops bug (logged share, leaked from infrastructure) | Team's eventual post-mortem cites infrastructure (key file leak, container escape, log file disclosure) | Team's post-mortem cites a specific GG20 paper / CVE |
| Alt: thornode signing bypass (no TSS compromise — sign via direct privilege escalation) | A path is found in thornode that allows non-quorum signing | Code review confirms TSS quorum strictly enforced |

### Confidence I'll have at each milestone

| Milestone | When | Expected confidence in official story |
|---|---|---|
| Now (status update only) | 2026-05-16 | ~70% |
| V1+V2+V3 done locally | 2026-05-16 (~1h) | ~80% if consistent |
| Official post-mortem with code citations | 2026-05-18 ~ 22 | ~95% |
| Independent third-party crypto audit confirms specific GG20 flaw | weeks later | ~99% |

### Verification log — V1, V2, V3, V4, V7 results (2026-05-16)

**V1 — Attacker node identified**:
- Full address: `thor16ucjv3v695mq283me7esh0wdhajjalengcn84q`
- Total bond: 635,331 RUNE (~$1.2M)
- Bond providers: `thor198ry37g…` (600,129 RUNE — main), `thor1e83t246w…` (35,200 RUNE), node itself only 1.99 RUNE
- Active since: **THORChain block 26,146,440 = 2026-05-12 17:36 UTC**
- Attack at: 2026-05-15 07:23 UTC → **~60 hour gap between activation and attack**

**V2 — TSS library version**:
- `go.mod` declares: `github.com/binance-chain/tss-lib v0.0.0-20201118045712-70b2cb4bf916`
- With replace directive: `=> gitlab.com/thorchain/tss/tss-lib v0.1.6`
- THORChain maintains its **own fork** at v0.1.6, based on the **2020-11 upstream version**
- Upstream `bnb-chain/tss-lib` reached **v2.0.0** which fixed CVE-2023-33241, TSSHOCK, etc.
- **THORChain fork at v0.1.6 has NOT pulled those upstream fixes**

**V3 — TSS code commits Apr-May 2026**:
- `cbf8f18a4` (Apr 9): "Batch resolve #2833/#2688/#2687/#2689" — adds new file `tss_round_normalizer.go` (105 lines) + `TssPhaseMessages.go` — suggests team was patching round-handling vulnerabilities
- `c9a7c23d9` (May 4): "Prioritize reading signer seed phrase from tmpfs file instead of env var" — operational hardening (env var → tmpfs)
- `1bfb5332c` (May 3): "Remove dead keysign party lookup path" — cleanup, low concern
- `8e909caf4`: "Validate signature count matches message count in keysign notifier" — security hardening against signature-count manipulation
- Pattern: team was actively patching TSS, attacker bonded AFTER the April security batch — either probing the patched system or finding paths that the patches didn't close

**V4 — Cross-referenced known TSS vulnerabilities**:
| CVE / Attack | Year | Impact | Fits 5/15 timeline? |
|---|---|---|---|
| [CVE-2023-33241](https://github.com/advisories/GHSA-5cjx-95fx-68q9) (Fireblocks, Paillier modulus check missing) | 2023 | **16 signatures suffice to extract full ECDSA private key** | 🟢 Yes — 16 sigs is ~minutes of vault activity |
| [TSSHOCK](https://verichains.io/tsshock/) (Verichains) | 2025 | Novel t-ECDSA key extraction; **explicitly names thornode TSS as tested target** | 🟢 |
| [α-shuffle](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) (Verichains, ambiguous encoding) | 2022 | PoC published against THORChain TSS specifically | 🟢 |
| [CVE-2023-26557](https://github.com/advisories/GHSA-mjqv-xhgm-gx8c) (timing side-channel, Paillier lambda) | 2023 | bnb-chain/tss-lib **AND** thorchain/tss explicitly named as affected | 🟢 |

The **CVE-2023-33241 "16 signatures suffice" finding resolves my earlier timeline concern**. I had assumed GG18/GG20 leakage needs hundreds of rounds; the actual fast-extraction CVEs need ~16. In 60 hours of an active vault signing committee, the attacker easily gets 16 rounds (vault signs ~50-200 outbounds/day per chain).

**V7 — Bond timeline (already captured above with V1)**.

### Updated confidence after V1-V7

| Claim | Pre-verification | Post V1-V7 |
|---|---|---|
| Official "GG20 leakage by single node" direction is correct | 70% | **~92%** |
| Specific class is CVE-2023-33241 (Paillier modulus) OR α-shuffle OR TSSHOCK variant | unknown | **~75%** that it's one of these or close variant |
| Simple operational bug (key on disk, log leak) dressed up as crypto attack | 25% | **~5%** — V3 shows real cryptographic patches were being applied; not consistent with ops-only attack |
| THORChain v0.1.6 fork lacks upstream v2.0.0 critical fixes | unknown | **~95%** — direct evidence from go.mod |
| 60h activation-to-attack window is feasible | flagged 🟡 | **~95%** — given 16-sig extraction class |

### My priors going in

- I was wrong about almost everything specific (H1-H6); my analytical
  process under-weighted the cryptographic layer entirely.
- The team has direct access to logs / signing-round transcripts /
  bond records that I don't.
- "GG20 leakage" is consistent with everything I observed on-chain.
- But: the team may also be **wrong or incomplete** — sometimes the
  initial "we know what happened" announcement is replaced 1-2 weeks
  later with a more accurate one.
- I will treat the official story as the working baseline (70%) until
  V1-V4 either corroborate or contradict.

---

## 12. Lessons added to Scryer audit pipeline

This incident is now anchored in two prompt directives:

1. [`prompts/solidity_audit_json_prompt.txt` — Hard rule: "Reachability proof
   for every claimed-exploitable finding"](../../prompts/solidity_audit_json_prompt.txt) — added as commit `aa920e9`. This rule would have caught my early
   over-claim of H1 by requiring me to verify the entry path before asserting
   exploitability.
2. [`prompts/solidity_audit_json_prompt.txt` — Off-Chain Trust Boundary
   directive](../../prompts/solidity_audit_json_prompt.txt) — added as commit
   `e4ec7e2`. Still valid for protocol-architecture analysis even though the
   5/15 attack was lower in the stack.

**Pending addition (TODO)**: a MPC/TSS directive for protocols that use
threshold signing — anchored on this incident. Audit auditors should
flag any Solidity contract whose fund safety depends on an off-chain MPC
implementation (vault contracts custodied by TSS, restaking validator
sets, multi-party-computed governance) and note that the cryptographic
protocol correctness is part of the trust surface even if out of audit
scope.
