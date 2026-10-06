# Incident Report — GMX V1 `globalShortAveragePrice` Lag via Cross-Contract Reentrancy

**Protocol**: GMX V1 (GLP liquidity pool · perpetual DEX)
**Chain**: Arbitrum One
**Date**: 2025-07-09
**Status**: Success (multi-tx exploit) — funds later returned
**Net loss**: ~$42M drained from the GLP vault; attacker returned ~$40M+ after GMX offered a 10% white-hat bounty (kept ≈ $5M). GMX separately finalized a ~$44M plan to compensate GLP holders.

---

## 0. TL;DR

GMX V1 prices GLP from the vault's Assets-Under-Management (AUM), and AUM *adds* the unrealized loss of all global shorts. That loss is computed from two values that are supposed to move together: `globalShortSizes[token]` (updated synchronously inside `increasePosition`) and `globalShortAveragePrice[token]` (updated through a different, keeper-executed path). The attacker opened a huge short through a **refund-callback reentrancy** so that `globalShortSizes` jumped immediately while `globalShortAveragePrice` still held a **stale** value. `getGlobalShortDelta()` then multiplied a *new, enormous size* against an *old average price* and a *manipulated mark price*, producing a phantom "short loss" that inflated AUM — and therefore GLP's redemption value. The attacker minted/redeemed GLP against the inflated AUM and drained the pool.

`nonReentrant` on the direct entrypoints did **not** stop this: the reentrancy was **cross-contract** (PositionRouter → vault callback → OrderBook), so a single-contract guard never covered the full path. The real fix is strict Checks-Effects-Interactions plus keeping size and average-price mutations atomic.

---

## 1. Affected components

| Component | Role in the bug |
|---|---|
| `GlpManager.getAum(bool maximise)` | Sums vault token inventory + unrealized global-short loss → feeds GLP price (`AUM / GLP supply`). |
| `GlpManager.getGlobalShortDelta(token, price, size)` | Compares current mark `price` vs `globalShortAveragePrice[token]`; returns `(delta, hasProfit)`. On loss, `delta` is added to AUM. |
| `Vault.globalShortSizes[token]` | Total open short size; **updated synchronously** in `increasePosition`. |
| `Vault.globalShortAveragePrice[token]` | Size-weighted average entry of all shorts; **updated on a different path** → the lag. |
| `PositionRouter.executeDecreaseOrder()` / `PositionManager` | Refunds surplus execution fee in native ETH → hands control to the attacker contract's `fallback()` (the reentrancy window). |

### The accounting identity being abused

Conceptually:

```
AUM = pool spot inventory + unrealized loss(global longs) + unrealized loss(global shorts)
```

GMX V1 in practice folds the global-short term into AUM as:

```
AUM = AUM + UnrealizedShortLoss
```

with

```
globalShortAveragePrice[token] = Σ(size_i · price_i) / Σ(size_i)
                               = Σ(size_i · price_i) / globalShortSizes[token]
```

The exploit concentrates on **global shorts** — the long side's accumulation/settlement path is structurally more stable and is commonly approximated as negligible for this attack (it is still computed, it just lacks the average-price desync that shorts have).

### The exploited code

```solidity
function getAum(bool maximise) public view returns (uint256) {
    // ...
    uint256 price = maximise ? vault.getMaxPrice(token) : vault.getMinPrice(token);
    // ...
    uint256 size = _vault.globalShortSizes(token);
    if (size > 0) {
        (uint256 delta, bool hasProfit) = getGlobalShortDelta(token, price, size);
        if (!hasProfit) {
            aum = aum.add(delta);          // <-- unrealized short LOSS is added to AUM
        } else {
            shortProfits = shortProfits.add(delta);
        }
    }
    // ...
}
```

When `globalShortSizes` has already jumped but `globalShortAveragePrice` lags, `getGlobalShortDelta` returns a grossly exaggerated `delta` with `hasProfit = false`, and `getAum` adds that fiction to AUM.

---

## 2. Root cause

**Cross-contract (read-only-style) reentrancy over a state-synchronization lag.**

The direct entrypoints carry `nonReentrant`, but the attack never re-enters the *same* guarded function. It rides the **execution-fee refund** in `executeDecreaseOrder()`: GMX refunds surplus ETH to the position owner, and because GMX does not distinguish an EOA from a contract, the refund `call` lands in the attacker contract's `fallback()`. From inside that callback the attacker mutates global short state (`vault.increasePosition(...)`) and schedules keeper-executed price updates — all while the outer order is mid-flight. The two short variables are momentarily inconsistent, and every AUM read in that window is poisoned.

> `ReentrancyGuard` cannot defend cross-contract reentrancy — the invariant has to come from Checks-Effects-Interactions and from keeping `globalShortSizes` and `globalShortAveragePrice` mutually consistent at every externally observable point.

---

## 3. Attack flow

**Phase 1 — Build an ETH position.**
Open an ETH long via the OrderBook; keeper executes `executeIncreaseOrder`.

**Phase 2 — Reentrancy / price-poisoning loop.**
Create a decrease order to close half the ETH position. On execution, GMX refunds surplus ETH → attacker `fallback()` fires. Inside the callback:
- `vault.increasePosition(USDC, BTC, short, hugeSize)` — `globalShortSizes[BTC]` jumps instantly.
- `positionRouter.createDecreasePosition(..., callback = this)` — schedule a keeper close with a forged price (`setPricesWithBits`), which overwrites `globalShortAveragePrice` and re-enters via `gmxPositionCallback`.
- Recurse: each iteration drags `globalShortAveragePrice[BTC]` further from the mark, deepening the phantom loss.

**Phase 3 — Profit extraction.**
With AUM inflated (GLP overpriced), flash-borrow USDC, open a massive BTC short while the price is still poisoned so the vault registers a huge GLP "loss", then `unstakeAndRedeemGlp` to convert the over-valued GLP back into underlying assets and drain the pool. Repay the flash loan, keep the difference.

```mermaid
sequenceDiagram
    participant Attacker
    participant OrderBook as OrderBook / PositionManager
    participant Router as PositionRouter / FastPriceFeed
    participant Vault as Vault + GLP

    Note over Attacker,Vault: Phase 1 — build ETH position
    Attacker->>OrderBook: createIncreaseOrder (ETH long)
    OrderBook->>Vault: keeper executeIncreaseOrder

    Note over Attacker,Vault: Phase 2 — callback / reentrancy loop
    Attacker->>OrderBook: createDecreaseOrder (close half ETH)
    OrderBook->>Vault: keeper executeDecreaseOrder
    Vault-->>Attacker: refund surplus ETH (no receive() ⇒ fallback)
    activate Attacker
    Note left of Attacker: fallback() runs
    Attacker->>Vault: increasePosition(USDC, BTC, short, hugeSize)
    Attacker->>Router: createDecreasePosition(callback=this)
    deactivate Attacker
    Router->>Vault: executeDecreasePosition (forged price)
    Note right of Vault: globalShortAveragePrice overwritten; size already huge
    Vault-->>Attacker: gmxPositionCallback → loop

    Note over Attacker,Vault: Phase 3 — profit extraction
    Attacker->>Vault: flashloan USDC, open massive BTC short (price poisoned)
    Router->>Vault: executeDecreasePosition → registers phantom GLP loss
    Attacker->>Vault: unstakeAndRedeemGlp (drains assets)
    Attacker->>Attacker: repay flashloan, keep profit
```

---

## 4. Reproduction (Foundry mainnet fork)

Pinned one block before the attack so contract code, storage and balances match the pre-exploit state:

```solidity
vm.createSelectFork("arbitrum", 355878385 - 1);
```

- **Keeper impersonation** — GMX gates order/price execution behind privileged keepers (`onlyKeeper`). In the fork we `vm.startPrank(orderBookKeeper)` / `vm.startPrank(routerPositionKeeper)` to drive `executeIncreaseOrder`, `executeDecreaseOrder` and `fastPriceFeed.setPricesWithBitsAndExecute`, modeling the async keeper pipeline inside one test.
- **Flash-loan stand-in** — `deal(usdc, attacker, amount)` / `vm.deal(attacker, 2 ether)` write the balance slot directly, standing in for the flash loan without implementing the borrow leg.
- **Instrumentation** — log vault balances and `glpManager.getGlobalShortAveragePrice(btc)` "before" vs "after" each reentrancy hop to watch the average price being dragged down.

### Observed effect (PoC console)

`globalShortAveragePrice(BTC)` collapses across reentrancy iterations as the stale average is repeatedly re-weighted against the poisoned size/price:

```
getGlobalShortAveragePrice(BTC) = 108757787000274036210359376021024492   // start (stale)
getGlobalShortAveragePrice(BTC) = 108757787000274036210359376021024492
getGlobalShortAveragePrice(BTC) = 104920450819574104703071455805467392
getGlobalShortAveragePrice(BTC) =  84258414874985604500133361231344758
getGlobalShortAveragePrice(BTC) =  35851226766120725985687797041267055
getGlobalShortAveragePrice(BTC) =   7258756616538433250522682128257390   // poisoned
```

Each drop widens the gap between the "average entry" the accounting believes and the real mark, which is exactly the phantom short loss that gets added to AUM.

---

## 5. Impact

- GLP is priced as `AUM / GLP_supply`. Inflating AUM inflates every GLP redemption, so the attacker converts cheap, over-valued GLP into real vault assets.
- Multi-asset drain of the GLP vault on Arbitrum — ETH, BTC, USDC, USDT, DAI, FRAX, LINK, UNI, USDe — totaling ~$42M.
- Systemic, not a price-feed glitch: the mispricing came from GMX's own internal accounting desync, so every integrator reading GLP/AUM in that window saw the inflated value.

---

## 6. Fix / defenses

1. **Checks-Effects-Interactions**, not just `nonReentrant`. The refund/callback must happen after all state is finalized; never hand control to an external address while short accounting is half-updated.
2. **Keep `globalShortSizes` and `globalShortAveragePrice` atomic.** Any path that changes one must update the other in the same state transition, so no externally observable point sees a size/avg-price mismatch.
3. **Harden AUM reads.** Treat `getAum` as reentrancy-sensitive (read-only reentrancy): guard it, or snapshot short state so mid-callback reads cannot consume an inconsistent pair.
4. **Refund hygiene.** Pull-over-push for execution-fee refunds, or bound the refund path so it cannot re-enter position/price mutation.

---

## 7. Detection rule

This incident informs the `zero_slippage_amm` / internal-accounting-desync rule family in [`rules/`](../rules/): flag share/AUM pricing that (a) reads a size and an average/price that are mutated on different paths, and (b) is reachable while an external `call`/refund is in flight. The high-signal pattern is an AUM or share-price view that folds in position PnL using a stored average that a reentrant path can desynchronize from the live size.

---

### References

- GMX $42M exploit root-cause write-ups (Verichains, SolidityScan, QuillAudits, Sherlock, CertiK).
- Fund return & GLP compensation: attacker returned ~$40M+ after a 10% white-hat bounty offer; GMX finalized a ~$44M GLP compensation plan (Aug 2025).
- Companion reproduction notes (original, zh): HackMD `@IceTeaSec/H1Pu7FVZWx`.
