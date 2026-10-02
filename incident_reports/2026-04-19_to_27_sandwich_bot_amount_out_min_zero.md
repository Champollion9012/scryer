# Incident Report — Serial Sandwich Bot Exploiting `amountOutMin=0`

**Scope**: 4 confirmed sandwich attacks on 4 distinct ERC-20 tokens
**Window**: 2026-04-19 → 2026-04-27 (9 days)
**Chain**: Ethereum Mainnet
**Status**: Ongoing — bot still active on 2026-04-27; not labelled on Etherscan
**Aggregate profit**: ≈ $12-15k WETH (small individual hits; volume play)

---

## 1. The actor

| Role | Address | Notes |
|---|---|---|
| **Attacker EOA** | [`0xF85e7038DaDf1b7ab97BA71528269d82328B7ba4`](https://etherscan.io/address/0xF85e7038DaDf1b7ab97BA71528269d82328B7ba4) | First seen 2026-01-13; 27 tx total; no Etherscan label |
| Mayan forwarder | `0x87a26566dbb3bf206634c1792a96ff4989e3f56e` | Cross-chain exit |
| Odos Router V3 | `0x0d05a7d3448512b78fa8a9e46c4872c88c4a0d05` | Token conversion |
| WETH (unwrap) | `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` | Final settle |

Bot's operating pattern: deploy a fresh attack contract per cycle (CREATE, no CREATE2), call its `flash(...)` entrypoint to execute the V4-flashloan + V2-sandwich + V4-repay sequence in one tx, then `Withdraw` WETH from WETH9, then Mayan-bridge profits out. No selfdestruct of attack contracts; all are still on-chain with bytecode.

---

## 2. Victim corpus (4 confirmed)

| # | Date | Token | Address | Verified? | Vuln line(s) | Profit |
|---|---|---|---|:---:|---|---|
| 1 | 2026-04-19 07:40 | "Asteroid Oli..." | [`0x7c5e0f17...b70b`](https://etherscan.io/address/0x7c5e0f17f5bb2d76d5f752d9ef4e0cdcb8bfb70b) | ✅ | swap L553 + addLiq L613 | 0.016 WETH (~$37) |
| 2 | 2026-04-23 22:39 | AIB ("America is Back") | [`0xb3a0f70c...30b6`](https://etherscan.io/address/0xb3a0f70c913aa04404bd177be9e20b47613830b6) | ✅ | swap L609 + addLiq L713 | 0.721 WETH (~$1,627) |
| 3 | 2026-04-26 07:24 | Saint Michael the Archangel | [`0x08495023...4ca0`](https://etherscan.io/address/0x08495023d2d331c61195a47f0143ed4c43544ca0) | ✅ | swap L286 + addLiq L333 | 1.577 WETH (~$3,748) |
| 4 | 2026-04-27 13:32 | UPEGSTR (UnipegStrate) | [`0xd730b101...210c`](https://etherscan.io/address/0xd730b101790e90051ee2db099ac8ee2c160d210c) | ✅ | `_buyAndBurnTokens` L398 | 3.63M UPEGSTR + ETH spread |

Per-cycle attack contracts (all unverified, all still on-chain with bytecode):

- 2026-04-19: `0x8f9ac463...`, `0xfe92df68...`
- 2026-04-23: `0xb4936c61...`
- 2026-04-26: `0x53263b1c...` (Archangel attack contract; analysed in detail)
- 2026-04-27: `0xf2b7c1e1...`, `0x3f7167c6...`, `0xb6c7efee...`

---

## 3. Root cause — single bug class

**Every victim** passes `amountOutMin = 0` to Uniswap V2's swap functions, with no off-chain slippage computation, no TWAP oracle, no fallback. The token's own auto-tax / auto-burn mechanism triggers the unprotected swap; the bot sandwiches that swap from the mempool.

The three SafeMoon-template victims (Asteroid / AIB / Archangel) share verbatim code:

```solidity
function swapTokensForEth(uint256 tokenAmount) private lockTheSwap {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();
    _approve(address(this), address(uniswapV2Router), tokenAmount);
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,                  // ← amountOutMin
        path,
        address(this),
        block.timestamp     // ← deadline (also bad, secondary)
    );
}
```

UPEGSTR (Solady-based, V4-hook strategy contract — architecturally completely different) has the **same bug** in its burn path:

```solidity
function _buyAndBurnTokens(uint256 amountIn) internal {
    address[] memory path = new address[](2);
    path[0] = V2_ROUTER.WETH();
    path[1] = address(this);
    V2_ROUTER.swapExactETHForTokensSupportingFeeOnTransferTokens{value: amountIn}(
        0, path, DEAD, block.timestamp     // ← amountOutMin=0 first positional
    );
}
```

So the bot's monoculture is not "SafeMoon clones" — it is **"any contract that auto-swaps with `amountOutMin=0`"**. Verified Solady-based protocols are not immune.

---

## 4. Why all 4 swap calls are multi-line — and what that means for scryer

**Status as of 2026-09-17: fixed in the regex layer.** `run_regex_scan` now matches every rule against the whole file (`rules_version: 3`) instead of line-by-line, so `\s*` / `[^,)]+` inside a rule can cross a newline. Re-running the pre-scan below gives **4/4 on the primary `amountOutMin=0` bug**:

| Victim | `UNISWAP_SWAP_*_AMOUNT_OUT_MIN_ZERO` | `UNISWAP_ADD_LIQUIDITY_ZERO_MIN` |
|---|---|---|
| Asteroid `0x7c5e0f17` | L553–557 | L613 |
| AIB `0xb3a0f70c` | L609–613 | L713 |
| Archangel `0x08495023` | L581–585 | L671 |
| UPEGSTR `0xd730b101` | L272–273 (`swapExactTokensForETH…`) + **L398–399 (`_buyAndBurnTokens`, ETH-first rule)** | L171–174 (multi-line, now caught) |

Each finding carries `line` (call start) and `end_line` (where the `0,` argument sits) so a reviewer lands on the right span. Regression tests: `tests/python/test_zero_slippage_rules.py::test_archangel_swap_multiline_is_caught`, `::test_upegstr_eth_for_tokens_multiline_is_caught`, `::test_add_liquidity_multiline_zero_min_is_caught`.

*Historical note (April–September 2026):* the original scanner was line-by-line and could not match a call whose `(` was on one line and `,\s*0\s*,` on the next. All four victims write the swap call that way, so regex catch rate on the primary bug was **0/4**; only the single-line `addLiquidityETH(_, _, 0, 0, _, _)` in `openTrading()` hit, on 3/4 victims (Asteroid, AIB, Archangel; rule pack commit `25460ab`).

The LLM stage of `audit_contracts.py` independently catches the multi-line swap — see [runs/archangel_audit](../runs/archangel_audit/groups/1_0x08495023d2d331c61195a47f0143ed4c43544ca0/report.md) F-03 (Sonnet 4.6, $0.39, 73k+11k tokens). The `MANDATORY-2 Numeric Input Bounds` directive in the prompt template is what surfaces it. With both layers firing, the regex pre-scan is now a reliable zero-cost triage for this bug class.

---

## 5. Repro

```bash
# Download verified sources (all 4 are verified on Etherscan, no decompile needed)
for addr in \
    0x7c5e0f17f5bb2d76d5f752d9ef4e0cdcb8bfb70b \
    0xb3a0f70c913aa04404bd177be9e20b47613830b6 \
    0x08495023d2d331c61195a47f0143ed4c43544ca0 \
    0xd730b101790e90051ee2db099ac8ee2c160d210c; do
  python download_contract.py --chain-id 1 --quiet "$addr"
done

# Fast regex pre-scan (4/4 on the primary swap bug since rules_version 3 / whole-file matching)
python -c "
from pathlib import Path
from scanners import load_rules_from_file, run_regex_scan
rules = load_rules_from_file(Path('rules/zero_slippage_amm.json'))
for addr in [
    '0x7c5e0f17f5bb2d76d5f752d9ef4e0cdcb8bfb70b',
    '0xb3a0f70c913aa04404bd177be9e20b47613830b6',
    '0x08495023d2d331c61195a47f0143ed4c43544ca0',
    '0xd730b101790e90051ee2db099ac8ee2c160d210c',
]:
    print(addr, run_regex_scan(list(Path('sources').glob(f'1_{addr}*.sol')), rules=rules)['findings'])"

# Full LLM audit (also catches all 4; needed for the semantic write-up, no longer for detection)
python audit_contracts.py \
    --chain-id 1 \
    --address 0x08495023d2d331c61195a47f0143ed4c43544ca0 \
    --provider claude --model claude-sonnet-4-6 \
    --regex-rules rules/zero_slippage_amm.json \
    --run-dir runs/archangel_audit
```

---

## 6. Scryer changes this incident motivated

| Commit | What | Validates against |
|---|---|---|
| `25460ab` | `rules/zero_slippage_amm.json` rule pack + 14 tests, including a pinned-limitation test for the multi-line regex blind spot | 3/4 victims on `addLiquidity`, 0/4 on the primary swap rule (regex layer) |
| 2026-09-17 (this branch) | `scanners.run_regex_scan` switched to whole-file matching (`rules_version: 3`, findings gain `end_line`); `UNISWAP_ADD_LIQUIDITY_ZERO_MIN` uses `[^;]*?` instead of `.*?` so it also spans lines; blind-spot test rewritten as a positive catch | **4/4 victims (regex layer)**, 0 lost findings on 201 local sources, ~1.9× faster scan |
| Earlier in branch — `12ecb3b` `feat(audit): force trusted-role threat enumeration + numeric bounds audit in prompt` | The `MANDATORY-2 Numeric Input Bounds` directive that the LLM uses to catch the multi-line case | 4/4 victims (LLM layer) |

---

## 7. Open follow-ups

- **Bot still active**: `0xF85e7038...` continued deploying attack contracts on 2026-04-27 after the latest sample analysed here. Worth a periodic re-poll to extend the corpus.
- **No on-chain label**: Etherscan has not tagged this EOA as "MEV Bot" or "Sandwich Bot". Could submit a tag suggestion via Etherscan's address-info feature.
- **scryer_whale_watcher integration**: the watcher monitors *stablecoin* recipients but doesn't index sandwich victims. A second watcher mode that polls `swapExactTokensForETHSupportingFeeOnTransferTokens` events on V2 pairs and flags ones with `amountOutMin=0` in the calldata could pre-emptively warn users before they ship a SafeMoon-template token.
- **End-to-end regression fixture**: turn this 4-victim corpus into `tests/python/fixtures/mev_sandwich_corpus.py` so any future scryer change that regresses catch rate fails CI. Not done yet.
