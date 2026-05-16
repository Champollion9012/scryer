# TSS Equivocation Attack — Pedagogical PoC

A local-runnable Go demonstration of the **bug class** behind the
2026-05-15 THORChain $10.8M drain. Mirrors the structure of TSSHOCK
(Verichains 2023) and CVE-2023-33241 (Fireblocks Paillier), without
being the real Verichains exploit code.

## Run it

```bash
cd incident_reports/2026-05-15_thorchain_secure_plus_drain/tss_demo
go test -v
```

Pure Go, no external dependencies, compiles on Windows / macOS / Linux
with Go 1.21+.

## What it shows

| # | Test | What it demonstrates |
|---|---|---|
| 1 | `TestHonestProtocolBindingHolds` | Length-prefixed commitment binds; Mallory cannot influence joint randomness after seeing Alice's. |
| 2 | `TestAttackEquivocationLeaksControl` | Without strict binding, Mallory can retro-fit her share so the joint value lands on her target. Joint r becomes attacker-controlled. |
| 3 | `TestDefenseStrictBindingBlocksAttack` | Strict-binding (length-prefix) commitment makes the retro-fit infeasible — even 1000 trial salts find no collision. |
| 4 | `TestControlledNonceRecoversPrivateKey` | **REAL ECDSA**: given a known signing nonce `k` (the consequence of #2 in real TSS), Mallory recovers the full ECDSA private key from **one** signature via `x = (s*k − z) * r⁻¹ mod n`. The recovered key matches the victim's key byte-for-byte. |

## What is real vs. simulated

| Part | Real or simulated | Notes |
|---|---|---|
| ECDSA over P-256 | **Real** | Uses Go stdlib `crypto/ecdsa` + `crypto/elliptic`. Signing math is identical to what hardware wallets / vaults do. |
| Key recovery formula | **Real** | Textbook `x = (s*k - z) * r⁻¹ mod n`. Same math that stole the PS3 firmware key (2010) and various wallet incidents. |
| SHA256 commitments | **Real** | Honest commitments are genuinely binding under SHA256 collision resistance. Test #3 demonstrates this empirically. |
| Test #2 equivocation step | **Simulated** | Test #2 cannot literally find a SHA256 second-preimage in a unit test (would need ~2²⁵⁶ work). Instead it models the *post-condition* of equivocation — that Mallory has effectively bound her commitment to a target — to demonstrate the **downstream effect** of an ambiguity-based attack. In real TSSHOCK / α-shuffle, the same effect is achieved via genuine protocol-level ambiguities in message serialization (not a SHA256 break). |

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
