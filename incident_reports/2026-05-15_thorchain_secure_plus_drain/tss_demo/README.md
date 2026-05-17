# TSS Attack PoCs — local reproductions of the 2026-05-15 bug class

Four local-runnable Go test files / setups that reproduce the
cryptographic bug class behind the THORChain $10.8M drain:

| File | Attack class | Status |
|---|---|---|
| `equivocation_attack_test.go` | α-shuffle / TSSHOCK encoding-ambiguity → controlled nonce → ECDSA key recovery | Pedagogical (final ECDSA step is real, middle step is simulated effect) |
| `paillier_modulus_attack_test.go` | **CVE-2023-33241 (Paillier modulus check missing) → full share recovery via CRT** | **Real cryptographic reproduction** — recovers a randomly generated 256-bit share byte-for-byte |
| `verify_bypass_test.go` | **Verbatim Go transcription of the vulnerable lib's verify logic** | Reproduces `(*Proof).Verify` from `gitlab.com/thorchain/tss/tss-lib v0.1.6` (paillier.go:240-277) verbatim and shows the malicious N passes both Part A (trial division) and Part B (Goldwasser proof) |
| `real_lib_run/attack_real_lib_test.go` | **Full end-to-end against the actual vulnerable lib** (WSL/Linux only) | Three tests using real `paillier.PublicKey.Encrypt` + `(*Proof).Verify` + `PrivateKey.Decrypt`: (1) 1024-bit `share mod 1009` leak in 0.08s; (2) **2048-bit production-scale** leak in 3.85s; (3) **full 256-bit ECDSA share recovered byte-for-byte via 26 sessions + CRT in 19.21s**. Captured outputs in `real_lib_run/run_output.txt`. |

## Run it

```bash
cd incident_reports/2026-05-15_thorchain_secure_plus_drain/tss_demo
go test -v
```

Pure Go, no external dependencies, compiles on Windows / macOS / Linux
with Go 1.21+.

## What it shows

### equivocation_attack_test.go (α-shuffle bug class)

| # | Test | What it demonstrates |
|---|---|---|
| 1 | `TestHonestProtocolBindingHolds` | Length-prefixed commitment binds; Mallory cannot influence joint randomness after seeing Alice's. |
| 2 | `TestAttackEquivocationLeaksControl` | Without strict binding, Mallory can retro-fit her share so the joint value lands on her target. Joint r becomes attacker-controlled. (Effect-modeled — see honesty section.) |
| 3 | `TestDefenseStrictBindingBlocksAttack` | Strict-binding (length-prefix) commitment makes the retro-fit infeasible — 1000 trial salts find no collision. |
| 4 | `TestControlledNonceRecoversPrivateKey` | **Real P-256 ECDSA**: given a known signing nonce `k`, Mallory recovers the full ECDSA private key from **one** signature via `x = (s*k − z) * r⁻¹ mod n`. Recovered key matches victim's byte-for-byte. |

### paillier_modulus_attack_test.go (CVE-2023-33241 — the **most likely** actual vector)

| # | Test | What it demonstrates |
|---|---|---|
| 1 | `TestPaillierHonestRunHidesSecret` | Standard 512-bit Paillier with two equal-size prime factors — ciphertexts hide their plaintexts as the scheme guarantees. |
| 2 | `TestPaillierAttackLeaksSecretModSmall` | Malicious Paillier with N = p_big × 65537. When the victim encrypts a 256-bit share under this N, the attacker recovers `share mod 65537` — leaking 17 bits per session. |
| 3 | `TestPaillierFullKeyRecoveryViaCRT` | **Full key recovery, real math, real numbers**: 24 sessions with different small-prime moduli → CRT-combined residues → `knownModulus ≥ 2^256` → full 256-bit ECDSA share recovered byte-for-byte. This is the actual CVE-2023-33241 mechanism that the THORChain v0.1.6 fork is unpatched against. |

### verify_bypass_test.go (proves the malicious N passes the *real* vulnerable lib)

| # | Test | What it demonstrates |
|---|---|---|
| 1 | `TestMaliciousPaillierPassesVulnerableLibVerify` | Reproduces `(*Proof).Verify` from `gitlab.com/thorchain/tss/tss-lib v0.1.6` (crypto/paillier/paillier.go:240-277) **verbatim**: trial-division for primes < 1000 (Part A) + Goldwasser-style "knows factorization" proof (Part B, ProofIters=13). Generates a malicious N = p_big × 1009 (smallest q_small that bypasses Part A). **Both parts accept the malicious N.** The same `Verify` is called per-peer in `ecdsa/keygen/round_4.go:42`, so this is the exact code path that admits the attack into the protocol. |
| 2 | `TestObviouslySmallFactorIsRejected` | Sanity: q_small=7 (< 1000) **is** rejected by Part A — confirms our reproduction of the vulnerable lib's check is faithful (not permissive of everything). |

## What is real vs. simulated

| Part | Real or simulated | Notes |
|---|---|---|
| **Paillier crypto system** | **Real** | Pure `math/big`. Keygen, encrypt, decrypt are textbook Paillier (1999). |
| **CVE-2023-33241 mechanism** | **Real** | The attacker generates a Paillier N with a smuggled small prime, encrypts a real victim share under it, recovers the share mod q_small via partial decryption, and CRT-combines residues across sessions. The recovered 256-bit share matches the original byte-for-byte. |
| ECDSA over P-256 | **Real** | Uses Go stdlib `crypto/ecdsa` + `crypto/elliptic`. Signing math is identical to what hardware wallets / vaults do. |
| Key recovery from known nonce | **Real** | Textbook `x = (s*k - z) * r⁻¹ mod n`. Same math that stole the PS3 firmware key (2010). |
| SHA256 commitments (test #1, #3) | **Real** | Honest commitments are genuinely binding under SHA256 collision resistance. Test #3 demonstrates this empirically — 1000 trial salts fail. |
| **Equivocation effect (test #2 only)** | **Simulated** | A unit test cannot literally find a SHA256 second-preimage (would need ~2²⁵⁶ work). Test #2 models the *post-condition* of equivocation to demonstrate the downstream effect. In real TSSHOCK / α-shuffle, the same effect is achieved via genuine protocol-level ambiguities in message serialization. (The Paillier test is the rigorous one if you want a single real-math reproduction.) |

### Calibration vs the real attack

| Parameter | Real CVE-2023-33241 | This demo | Effect |
|---|---|---|---|
| Paillier modulus size | 2048 bit | 512 bit | Demo runs in <1 s |
| Small-prime factor q_small | ~32 bit | 13–17 bit | Demo needs more sessions but each runs instantly |
| Sessions needed to recover 256-bit share | ~16 | 24 (this run) | Same math, different parameters |
| Recovery technique | CRT over multiple sessions | **Identical** | — |

## Mapping to the real 2026-05-15 attack

The full attack chain:

```
THORChain churn cycle (5/12)
        │
        ▼
Attacker node joins keygen ceremony of new Asgard vault
        │
        ▼   [TSSHOCK α-shuffle / CVE-2023-33241 / similar]
        │   Exploit ambiguity in vulnerable tss-lib v0.1.6 fork
        │
        ▼
Mallory effectively "biases" or "extracts" key material during keygen
        │   ← This is what tests #1, #2, #3 in this demo are about
        │
        ▼
Mallory has knowledge equivalent to the aggregate ECDSA private key
        │   ← Test #4 demonstrates: this is enough to forge any sig
        │
        ▼
Mallory signs ETH/BTC/BSC/Base/AVAX transactions directly from the
vault's address. No further protocol interaction with THORChain needed.
        │
        ▼
$10.8M drained over ~3 hours (5/15 07:23 ~ 10:30 UTC)
```

The exact protocol-level bug Verichains used in TSSHOCK is intentionally
withheld from the public to limit damage (responsible disclosure). The
demo here uses a stand-in (commitment without length prefix) that is
**structurally analogous** — both are "encoding ambiguity allows a
single malicious party to bypass binding guarantees that the protocol
relied on".

## What this demo proves about the real attack

1. **Single malicious participant is enough.** No collusion required.
   Tests #2 and #4 both show 1 attacker, 1 victim.
2. **Strict encoding hygiene is load-bearing security.** Test #3 shows
   that the SAME protocol becomes safe just by length-prefixing the
   commitment. The bug is in the **bytes**, not in the cryptography.
3. **One signature can leak the full key once the nonce is known.**
   Test #4 demonstrates the textbook recovery — this is the
   irreversible step that makes any TSS nonce-control bug catastrophic
   rather than merely worrying.
4. **The defender must verify, not just hash.** Length-prefixing isn't
   optional. Any TSS protocol that hashes structured data must encode
   the structure unambiguously, or all the elegant cryptography around
   it can be undone by a parser disagreement.

## What this demo does NOT do

- Does **not** implement the real TSSHOCK / α-shuffle / CVE-2023-33241
  exploit code (Verichains responsibly withheld it).
- Does **not** target a real `bnb-chain/tss-lib` or `thorchain/tss-lib`
  installation (full reproduction would require running the GG18/GG20
  protocol with multiple parties on a vulnerable version).
- Does **not** publish any new attack capability. The equivocation
  bug class has been known since at least 2022 in academic literature.

## Further reading

- [TSSHOCK (Verichains, Black Hat USA 2023)](https://verichains.io/tsshock/) — α-shuffle, c-split, c-guess, names THORChain
- [CVE-2023-33241](https://github.com/advisories/GHSA-5cjx-95fx-68q9) — Fireblocks Paillier modulus check missing (16 sigs → full key)
- [CVE-2023-26557](https://github.com/advisories/GHSA-mjqv-xhgm-gx8c) — bnb-chain/tss-lib AND thorchain/tss explicitly named
- [Trail of Bits: "Breaking the shared key in threshold signature schemes" (2024-02)](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/)
- [bnb-chain/tss-lib v2.0.0 release notes](https://github.com/bnb-chain/tss-lib/releases) — the upstream version with the fixes that THORChain's fork at v0.1.6 never pulled
