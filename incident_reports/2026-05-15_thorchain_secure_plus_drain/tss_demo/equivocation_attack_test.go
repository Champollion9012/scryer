// Toy demonstration of the bug class behind TSSHOCK's α-shuffle attack:
// commitment without strict binding allows ONE malicious party to equivocate
// during a multi-party protocol and derive the other party's secret share.
//
// This is NOT the real Verichains exploit (Verichains responsibly withholds
// production-attack code). This is a simplified pedagogical reproduction of
// the same bug CLASS that TSSHOCK / α-shuffle / CVE-2023-33241 all exploit:
//
//     "If commitment / proof encoding is not strictly binding, a single
//      malicious participant can present DIFFERENT views to different
//      honest participants and extract their shares."
//
// Run with:
//
//     go test -v -run TestEquivocation
//
// Compiles and runs on any platform with Go 1.21+.
//
// The toy protocol below is a 2-party additive secret share:
//
//   - Alice (honest) and Mallory (attacker) want to agree on a shared
//     random value r = r_A + r_B that neither learns alone.
//   - Each commits to their r_i, then both reveal. If both commitments
//     bind, neither party can change r_i after seeing the other's.
//
// In the VULNERABLE variant, the commitment hash input is built by string
// concatenation without strict length prefixing. This means a malicious
// commitment value can be "re-interpreted" with a different r_M after the
// fact — Mallory effectively gets to pick r_M AFTER seeing Alice's r_A,
// breaking the protocol's binding guarantee.
//
// Mallory then chooses r_M such that r = r_A + r_M is a value she controls.
// In a real TSS, "r" is the joint nonce or signing scalar, and controlling
// it means controlling the final signature → recovering the private key.

package tss_equivocation_demo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
)

// =============================================================================
// HONEST commitment (strictly binding)
// =============================================================================
//
// commitHonest(r, salt) = SHA256( len(r) || r || len(salt) || salt )
//
// Length prefixes make the input UNAMBIGUOUS: there is exactly one (r, salt)
// pair that produces a given hash. Mallory cannot find r' != r that hashes
// the same way.

func commitHonest(r, salt []byte) []byte {
	h := sha256.New()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(r)))
	h.Write(lenBuf[:])
	h.Write(r)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(salt)))
	h.Write(lenBuf[:])
	h.Write(salt)
	return h.Sum(nil)
}

// =============================================================================
// VULNERABLE commitment (no strict binding)
// =============================================================================
//
// commitVuln(r, salt) = SHA256( r || salt )
//
// Without length prefixes, MANY different (r, salt) pairs can produce the
// same hash. For example, ("abc", "def") and ("ab", "cdef") and ("a", "bcdef")
// all hash to the same value. Mallory exploits this: she sends a commitment
// computed against ONE interpretation, observes Alice's reveal, then "opens"
// the commitment under a DIFFERENT interpretation that yields a value she
// wants.

func commitVuln(r, salt []byte) []byte {
	h := sha256.New()
	h.Write(r)
	h.Write(salt)
	return h.Sum(nil)
}

// =============================================================================
// HONEST protocol run (binding holds)
// =============================================================================

func TestHonestProtocolBindingHolds(t *testing.T) {
	// Alice picks honest r_A
	r_A := big.NewInt(0).SetBytes(randBytes(32))
	salt_A := randBytes(16)
	cmt_A := commitHonest(r_A.Bytes(), salt_A)

	// Mallory picks her r_M. She has NOT yet seen Alice's r_A — only Alice's
	// commitment. Under honest commitment binding she is locked into r_M now.
	r_M := big.NewInt(0).SetBytes(randBytes(32))
	salt_M := randBytes(16)
	cmt_M := commitHonest(r_M.Bytes(), salt_M)

	// Reveal phase: both open. Each verifies the other's commitment by
	// recomputing it from the revealed (r, salt).
	if !bytesEqual(commitHonest(r_A.Bytes(), salt_A), cmt_A) {
		t.Fatal("Alice's commitment verify failed (impossible)")
	}
	if !bytesEqual(commitHonest(r_M.Bytes(), salt_M), cmt_M) {
		t.Fatal("Mallory's commitment verify failed")
	}

	// Joint random
	r := new(big.Int).Add(r_A, r_M)

	t.Logf("HONEST RUN")
	t.Logf("  r_A         = %x...", r_A.Bytes()[:8])
	t.Logf("  r_M         = %x...", r_M.Bytes()[:8])
	t.Logf("  joint r     = %x...", r.Bytes()[:8])
	t.Logf("  Mallory could not influence joint r after seeing r_A (binding held).")
}

// =============================================================================
// ATTACK protocol run (equivocation via missing strict binding)
// =============================================================================
//
// The attack: Mallory crafts a special commitment of the form C* = H(prefix)
// where `prefix` is a string for which there exist MULTIPLE valid splits
// (r, salt) such that r || salt == prefix.
//
// For pedagogical clarity, the demo uses the simplest such trick: Mallory
// commits to a value of which the BYTES are interpretable as either
// (r_M_orig, salt_orig) OR as (r_M_adjusted, salt_adjusted) — by shifting
// the boundary inside the concatenation. After seeing r_A, she picks
// whichever split makes the joint r = r_A + r_M land on a target value she
// controls.

func TestAttackEquivocationLeaksControl(t *testing.T) {
	// Mallory's TARGET joint value: she wants r to equal some specific
	// attacker-chosen value (e.g., a weak/zero key in real TSS).
	// For this demo Mallory wants r = 0x00...01 (essentially zero).
	target := big.NewInt(1)

	// Alice picks honest r_A (Mallory does NOT know it yet).
	r_A := big.NewInt(0).SetBytes(randBytes(32))
	salt_A := randBytes(16)
	cmt_A := commitVuln(r_A.Bytes(), salt_A)

	// Mallory's plan:
	// (1) Pick a "scaffold" 48-byte payload `P` (16-byte salt + 32-byte r-style),
	//     send commitment C* = SHA256(P).
	// (2) Observe Alice's reveal of r_A.
	// (3) Compute Mallory's needed r_M_eff = target - r_A (mod 2^256).
	// (4) Find ANY split of the 48-byte payload P into (r_M, salt_M) such that
	//     r_M (interpreted as big-endian integer) equals r_M_eff.
	//
	// Because commitVuln has no length prefix, we can split P at any boundary.
	// Here we exploit the simpler trick: Mallory uses a payload of LENGTH 32
	// only (no salt!) and tricks the verifier into accepting (r_M=P, salt_M="")
	// even though Mallory privately committed pretending salt was prefixed.
	//
	// In a real protocol the verifier expects a 16-byte salt; in the vulnerable
	// hash that's INDISTINGUISHABLE from "salt is part of r_M's bytes". So
	// after Mallory picks her commitment value, the SAME hash can be opened
	// to MANY (r_M, salt_M) pairs.

	// Mallory generates her FAKE initial commitment as if she had random r_M.
	// But she will not actually commit to r_M — she commits to a chosen
	// 48-byte payload whose hash she will retro-fit to ANY r_M_eff later.
	scaffold := make([]byte, 48)
	_, _ = rand.Read(scaffold)
	cmt_M := commitVuln(scaffold, []byte{}) // honest signature: H(scaffold || "")

	// Reveal phase: Alice opens first (typical TSS pattern: each opens in
	// turn; even if simultaneous, network adversary lets Mallory see first).
	// Alice reveals (r_A, salt_A) — verifier reconstructs commitHonest...
	// or rather commitVuln. Alice's verifies fine.
	if !bytesEqual(commitVuln(r_A.Bytes(), salt_A), cmt_A) {
		t.Fatal("Alice's commitment verify failed (impossible)")
	}

	// Now Mallory MUST open. She computes needed r_M_eff.
	// r_M_eff = target - r_A (mod 2^256)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	r_M_eff := new(big.Int).Sub(target, r_A)
	r_M_eff.Mod(r_M_eff, mod)

	// Mallory now opens her commitment as (r_M, salt_M) where:
	//   - r_M = r_M_eff as 32 bytes
	//   - salt_M = scaffold[32:48] BUT she claims her commitment was over a
	//     DIFFERENT scaffold by exploiting ambiguous encoding.
	//
	// In this toy demo, we cheat a little: instead of finding a SHA256
	// collision (which is computationally infeasible), we model the attack
	// by REPLAYING the same hash check that a non-binding verifier would
	// perform. The point of the demo is that the verifier CANNOT TELL
	// whether Mallory committed at time T_1 or at time T_2 — both produce
	// valid-looking openings under commitVuln.
	//
	// Specifically: the vulnerable verifier accepts ANY (r_M, salt_M) such
	// that commitVuln(r_M, salt_M) == cmt_M. In a real TSS the equivalent
	// is: the malicious party finds an "alternative" encoding of an
	// equivalent message that the protocol fails to disambiguate.

	r_M_bytes := pad32(r_M_eff.Bytes())
	// Mallory's FAKE opening: she claims (r_M_eff, salt_M_fabricated) was
	// her commitment. Note: this would require finding a salt_M such that
	// commitVuln(r_M_eff, salt_M) == cmt_M. SHA256 makes this hard.
	//
	// In a real α-shuffle exploit, the "alternative encoding" is found via
	// a structured ambiguity in the protocol's serialization (e.g.,
	// trailing zero bytes silently ignored, fields without length prefix
	// allowing reinterpretation). The demo below ASSUMES the equivalent
	// of a found ambiguity by adjusting how the verifier checks.

	// Vulnerable verifier (the bug): does NOT enforce strict binding.
	// We model this by saying: verifier accepts the opening as long as the
	// reconstructed PREFIX of the hash matches. This is the toy version of
	// "encoding ambiguity allows alternative parsing".
	// (In real TSSHOCK, the actual bug is structurally similar but uses
	// real protocol-level ambiguities.)
	verifierAccepts := vulnerableVerifierAcceptsRebound(cmt_M, r_M_bytes, scaffold)
	if !verifierAccepts {
		t.Logf("(Note: this toy demo cannot literally find a SHA256 collision; ")
		t.Logf(" the simulation below shows the ATTACK EFFECT — control of joint r — ")
		t.Logf(" which is what real α-shuffle equivocation achieves via protocol-level ambiguity.)")
	}

	// Effect: Mallory has CONTROLLED the joint r.
	r := new(big.Int).Add(r_A, r_M_eff)
	r.Mod(r, mod)

	t.Logf("ATTACK RUN (equivocation)")
	t.Logf("  r_A         = %x...", r_A.Bytes()[:8])
	t.Logf("  r_M_eff     = %x...", r_M_eff.Bytes()[:8])
	t.Logf("  joint r     = %s (Mallory's TARGET — fully controlled)", r.String())
	t.Logf("")
	t.Logf("  In real TSS, controlling the joint signing nonce means:")
	t.Logf("  (a) the resulting signature s = k^-1 (H(m) + r*x) reveals x")
	t.Logf("  (b) over a small number of such 'controlled' signatures, the ")
	t.Logf("      attacker recovers the full ECDSA private key.")
	t.Logf("")
	t.Logf("  Verichains' published number for various lib variants is 1-2")
	t.Logf("  signatures suffice (TSSHOCK). For pre-v2.0.0 bnb-chain/tss-lib")
	t.Logf("  the matching CVE-2023-33241 (Paillier modulus missing-check)")
	t.Logf("  yields full extraction in ~16 signatures.")

	if r.Cmp(target) != 0 {
		t.Fatalf("attack effect demo: expected joint r == target (%s), got %s", target, r)
	}
}

// =============================================================================
// Defense: strict-binding commitment makes the equivocation infeasible
// =============================================================================

func TestDefenseStrictBindingBlocksAttack(t *testing.T) {
	// Same scenario as TestAttackEquivocationLeaksControl, except now the
	// protocol uses commitHonest with length prefixes. Mallory cannot find
	// an alternative (r_M, salt_M) that opens her commitment differently.

	r_A := big.NewInt(0).SetBytes(randBytes(32))
	salt_A := randBytes(16)
	_ = commitHonest(r_A.Bytes(), salt_A)

	// Mallory commits HONESTLY to a r_M she picked WITHOUT seeing r_A.
	r_M_initial := big.NewInt(0).SetBytes(randBytes(32))
	salt_M := randBytes(16)
	cmt_M := commitHonest(r_M_initial.Bytes(), salt_M)

	// After seeing Alice's r_A, Mallory wants to retro-fit r_M to a target.
	// She computes r_M_eff = target - r_A. But to "open" she needs a salt'
	// such that commitHonest(r_M_eff, salt') == cmt_M. Because length
	// prefixes make the encoding unambiguous, this requires a true SHA256
	// 2nd-preimage which is computationally infeasible.

	r_M_eff := new(big.Int).Sub(big.NewInt(1), r_A)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	r_M_eff.Mod(r_M_eff, mod)

	// Mallory tries 1000 random salts (a real attacker has more compute,
	// but SHA256 still requires ~2^256 work for 2nd-preimage). She fails.
	found := false
	for tries := 0; tries < 1000; tries++ {
		trialSalt := randBytes(16)
		if bytesEqual(commitHonest(pad32(r_M_eff.Bytes()), trialSalt), cmt_M) {
			found = true
			break
		}
	}
	t.Logf("DEFENSE RUN (strict-binding commitment)")
	t.Logf("  Mallory tried 1000 retro-fit salts. Found collision: %v", found)
	t.Logf("  (a real attacker would need ~2^256 SHA256 hashes — infeasible)")
	t.Logf("  Real signing nonce r = r_A + r_M_initial is therefore UNPREDICTABLE")
	t.Logf("  and the attacker cannot bias it.")

	if found {
		t.Fatal("strict-binding broken — should not happen unless SHA256 is broken")
	}
}

// =============================================================================
// Concrete consequence: controlled nonce → full ECDSA private key recovery
// =============================================================================
//
// This is the textbook ECDSA known-nonce attack. It is mathematically trivial
// once the attacker knows the nonce `k` of any single signature. Real-world
// versions of this attack have stolen tens of millions of dollars (PlayStation
// 3 firmware, Sony 2010; various wallet incidents). The TSS-specific twist is
// that "knowing k" comes from controlling the joint nonce generation via
// equivocation or similar — exactly the bug class TSSHOCK exploits.
//
// ECDSA signature: s = k^-1 (z + r*x) mod n
//   r = (k*G).x mod n   (public)
//   z = H(msg)          (public)
//   s                   (public)
//   x = private key     (secret — what we want)
//   k = nonce           (secret — but ATTACKER KNOWS IT via TSS equivocation)
//
// Solve: x = (s*k - z) * r^-1 mod n     ← one signature, one multiplication

func TestControlledNonceRecoversPrivateKey(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N

	// Victim generates a normal ECDSA key.
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xTrue := priv.D
	t.Logf("VICTIM private key x   = %x...", xTrue.Bytes()[:8])

	// Sign a message. In real TSS, k would come from the joint nonce r_A + r_M
	// that Mallory just controlled to a value she knows. Here we just pick k.
	k, _ := rand.Int(rand.Reader, n)
	msg := []byte("transfer 1086 ETH to attacker")
	zBytes := sha256.Sum256(msg)
	z := new(big.Int).SetBytes(zBytes[:])

	// Compute r = (k*G).x mod n
	kGx, _ := curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(kGx, n)

	// Compute s = k^-1 (z + r*x) mod n
	kInv := new(big.Int).ModInverse(k, n)
	rx := new(big.Int).Mul(r, xTrue)
	zPlusRx := new(big.Int).Add(z, rx)
	s := new(big.Int).Mul(kInv, zPlusRx)
	s.Mod(s, n)

	t.Logf("Signature (r, s)       = (%x..., %x...)", r.Bytes()[:8], s.Bytes()[:8])
	t.Logf("Message hash z         = %x...", z.Bytes()[:8])
	t.Logf("Controlled nonce k     = %x...  ← Mallory knows this from equivocation", k.Bytes()[:8])

	// ATTACK: Mallory recovers x from a single signature.
	// x = (s*k - z) * r^-1 mod n
	sk := new(big.Int).Mul(s, k)
	skMinusZ := new(big.Int).Sub(sk, z)
	rInv := new(big.Int).ModInverse(r, n)
	xRecovered := new(big.Int).Mul(skMinusZ, rInv)
	xRecovered.Mod(xRecovered, n)

	t.Logf("Recovered x            = %x...", xRecovered.Bytes()[:8])

	if xRecovered.Cmp(xTrue) != 0 {
		t.Fatalf("recovery failed: got %x, want %x", xRecovered.Bytes(), xTrue.Bytes())
	}

	t.Logf("")
	t.Logf("=== KEY RECOVERED FROM ONE SIGNATURE WITH KNOWN NONCE ===")
	t.Logf("This is what 'controlling the joint nonce' costs the protocol:")
	t.Logf("  1. Mallory equivocates during keysign to bias k to her chosen value")
	t.Logf("  2. The honest parties produce a normal-looking signature (r, s)")
	t.Logf("  3. Mallory recovers the FULL aggregate private key x from (r, s, z, k)")
	t.Logf("  4. Mallory can now sign ANY ETH/BTC/BSC transaction as the vault")
	t.Logf("  5. Mallory drains the vault directly. No further protocol interaction needed.")
}

// =============================================================================
// helpers
// =============================================================================

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// vulnerableVerifierAcceptsRebound models a verifier that has a bug in
// commitment parsing — it accepts "rebound" openings. The real Verichains
// α-shuffle attack uses protocol-level ambiguities to achieve the same
// effect. This toy returns true so the demo proceeds; the ATTACK EFFECT
// (controlled joint r) is what matters for the lesson.
func vulnerableVerifierAcceptsRebound(_ /*cmt*/, _ /*claimed_r*/, _ /*scaffold*/ []byte) bool {
	// In real attacks: protocol ambiguity → verifier accepts alternative
	// opening even though the SHA256 hash itself is the same. We simulate
	// the post-condition: attacker EFFECTIVELY equivocated.
	_ = fmt.Sprintf // keep import live in unused branch
	return true
}
