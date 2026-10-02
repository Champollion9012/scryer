# Incident Report — `ycdeal` Redeem-Recipient Drain

**Tx**: `0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3`
**Chain**: Ethereum Mainnet
**Block / Time**: 24,979,316 — 2026-04-28 15:00:11 UTC
**Status**: Success (single-tx exploit)
**Net loss**: ~387,764 USDC (≈ $387,600) drained to attacker EOA

---

## 1. Actors

| Role | Address | Notes |
|---|---|---|
| Attacker EOA | [`0x7137...B56A`](https://etherscan.io/address/0x7137804200a073f616D92E87007f1f100100B56A) | Funded from Tornado.Cash; created 9 days before exploit |
| Attack contract | [`0x50C1...8d17`](https://etherscan.io/address/0x50C140C2f705Fa9d0bD0F4F253bacF4087588d17) | Unverified; bytecode contains literal `"Hack the world"`; deployed 8 days before exploit |
| Victim contract | [`0xb9c7...f88a`](https://etherscan.io/address/0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a) | `ycdeal...` — yield-bearing USDC token, 1 ycdeal ≈ 1 USDC |
| Bribe sink | [`0x4838...5f97`](https://etherscan.io/address/0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97) | Titan Builder (coinbase tip) |
| Liquidity used | `0xB4e1...C9Dc` USDC/WETH Univ2 pair, `0x7a25...488D` Univ2 Router 2 | Bribe swap leg |

---

## 2. Vulnerability — ERC4626 override drops `_spendAllowance`

**Confirmed root cause from verified source** (cross-referenced with the existing Scryer manual review at [`audit_reports/run_20260505_105059Z_exploit_review/report.md`](../audit_reports/run_20260505_105059Z_exploit_review/report.md), entry **F-01**, severity **Critical**).

The vault is `ycdeal3` RWAVault, source verified — see [`sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol`](../sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol). It custom-overrides both `withdraw(uint256, address, address)` (lines 651-716) and `redeem(uint256, address, address)` (lines 721-778). Both overrides:

1. Re-claim accrued interest for `owner` and transfer it **to `owner`** (correct — explains the small "yield" payments to victims).
2. Burn shares from `owner` (correct).
3. `safeTransfer(asset, receiver, assets)` to the **caller-supplied `receiver`** — without ever invoking `_spendAllowance(owner, msg.sender, shares)`.

Standard OpenZeppelin `ERC4626.withdraw` / `redeem` always call `_spendAllowance(owner, msg.sender, shares)` when `msg.sender != owner`. The override removed that gate. Anyone can call `withdraw(amount, attackerEOA, victimUser)` and route the assets to themselves.

`nonReentrant`, `whenNotPaused`, and the `Phase.Matured` / `withdrawalStartTime` checks are all present — none of them substitute for an allowance check, and the vault was already in `Matured` phase.

**Why prior audit missed it**: the file carries `[H-01 FIX]` markers around share/debt rounding (lines 691-702) — a previous review focused on rounding edge cases inside the override and did not flag the missing ERC4626 allowance invariant. Classic regression hazard when a project fully overrides ERC4626 entry points instead of using OZ's `_withdraw` / `_redeem` internal hooks.

> My initial digest (without source) identified the symptom correctly — "principal USDC is redirected to caller while holder's tokens are burned" — but framed it as a generic `redeemFor` access bug. Reading the source pinpoints it as an ERC4626 override that dropped `_spendAllowance`, which is a more specific and well-known anti-pattern.

---

## 3. Step-by-step

### Phase 1 — Batch drain of 8 holder positions

Attack contract calls the buggy entrypoint 8 times, once per known holder. Per call the on-chain effect is:

```
ycdeal contract → holder         :  yield_X USDC      (legitimate accrued yield)
holder          → 0x0            :  principal_Y ycdeal (burn)
ycdeal contract → attack contract:  ~principal_Y USDC (recipient bug)
```

| # | Holder | Yield paid (USDC) | ycdeal burned | USDC siphoned to attacker contract |
|---|---|---:|---:|---:|
| 1 | `0xC15D1F...D51b` | 150 | 100 | 100 |
| 2 | `0x982692...3e9a` | 18 | 1,200 | 1,200 |
| 3 | `0x5070Fa...8483` | 4,050 | 270,000 | 270,000 |
| 4 | `0xe95637...38B5` | 47.04 | 3,136 | 3,136 |
| 5 | `0x5A0E2b...7fee` | 95.70 | 6,380 | 6,380 |
| 6 | `0xC15D1F...D51b` (2nd hit) | – | 9,900 | 9,900 |
| 7 | `0x1Acb62...2fAA` | 30.73 | 2,048 | 2,048 |
| 8 | `0xaB2f2F...85Ae6` | 1,500 | 100,000 | 100,000 |
| **Σ** |  | **5,891 USDC** to holders | **392,764 ycdeal burned** | **392,764 USDC into attack contract** |

### Phase 2 — Builder bribe

Attack contract calls Univ2 Router `swapExactTokensForETH` with `to = Titan Builder`:

- 5,000 USDC → USDC/WETH pair → 2.195959995966763304 WETH → unwrapped → ETH delivered straight to Titan Builder.
- Coinbase-tip pattern; ensures ordering through Titan's private pipeline so the tx is not front-run or copy-mined from a public mempool.

### Phase 3 — Withdraw to EOA

- Attack contract → attacker EOA: **387,763.999994 USDC**.
- Math: 392,764 collected − 5,000 bribed = 387,764. ✓

---

## 4. Fund flow

```
ycdeal (0xb9c7) ─┬─ 5,891 USDC ──► 7 holders (legitimate yield, looks normal)
                 └─ 392,764 USDC ─► attack contract (0x50C1)
                                      │
                                      ├─ 5,000 USDC ─[Univ2]─ 2.196 ETH ─► Titan Builder (bribe)
                                      └─ 387,764 USDC ─────────────────► attacker EOA (0x7137)
```

---

## 5. Tactical observations

- **Quiet exfiltration**: paying yield correctly to the holder makes the drain look like a normal yield-distribution event in the victim's wallet history.
- **Pre-scoped target list**: 8 known holders all hit in one tx — attacker enumerated balances ahead of time; no probing in-tx.
- **Private inclusion**: ~1.3% of gross siphoned funds spent as builder tip, swap-and-pay model avoids holding ETH on the EOA before the attack.
- **OpSec**: EOA seeded from Tornado.Cash, attack contract pre-staged 8 days. Attacker was waiting for a window; the exploit itself is one tx.

---

## 6. Detection / rule status in `scryer`

- **Already shipped**: [`rules/unprotected_withdraw.json`](../rules/unprotected_withdraw.json) `ERC4626_WITHDRAW_REDEEM_OVERRIDE_SIG` — line-regex catching the `function (withdraw|redeem)(uint256, address, address)` override shape. Hits `RWAVault.sol:651` and `:721`. Signature alone cannot prove the body lacks `_spendAllowance`; any match warrants manual look.
- **Open ideas worth encoding**:
  1. AST/semantic check: an ERC4626 override that touches `_burn(owner, ...)` and `safeTransfer(asset, receiver, ...)` without calling `_spendAllowance` between them = critical.
  2. Mass-burn-to-zero-address heuristic for incident triage: same-tx 5+ ERC-20 burns from distinct `from` addresses, all driven by one external caller.
  3. Builder-bribe heuristic: outgoing ETH to a known builder (Titan, beaverbuild, rsync) within a tx whose bribe ≤ 2% of gross asset movement.

## 7. Cross-tool comparison

| Source | Severity | Identified root cause | Status |
|---|---|---|---|
| This digest (Claude, trace-only) | Critical | Recipient-confusion bug — caller-supplied recipient receives principal while holder's shares are burned | Symptom correct, mechanism inferred from logs |
| Scryer manual review F-01 (with source) | Critical | ERC4626 override of `withdraw`/`redeem` omits `_spendAllowance(owner, msg.sender, shares)` | ✅ confirmed in verified source, OZ comparison cited, fix path documented |
| **MiniMax M2.7 audit** | — | — | ⏳ **No run on file** — neither `audit_reports/` nor `runs/` contain a MiniMax provider output for this contract. Project's `llm_providers.py` currently registers only OpenAI / Claude / Gemini; routing MiniMax M2.7 via the OpenAI-compatible base URL is feasible but has not been executed. To compare, run `audit_contracts.py` against [`sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol`](../sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol) with `--base-url` pointed at MiniMax and `--model minimax-m2.7`. |

---

## 8. Sources

- [Etherscan transaction view](https://etherscan.io/tx/0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3)
- [Etherscan token transfers tab](https://etherscan.io/tx/0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3#tokentxns)
- Phalcon trace (auth-walled, not fetched): `https://app.blocksec.com/phalcon/explorer/tx/eth/0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3`
- Existing Scryer manual review F-01: [`audit_reports/run_20260505_105059Z_exploit_review/report.md`](../audit_reports/run_20260505_105059Z_exploit_review/report.md)
- Verified vault source: [`sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol`](../sources/1_0xb9c7c84a1aa0dd40b5b38aae815ad0cdd2e5f88a_src_vault_RWAVault.sol)
- Existing detection rule: [`rules/unprotected_withdraw.json`](../rules/unprotected_withdraw.json)
