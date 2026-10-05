# scryer MCP — forensic-layer improvement spec

Driven by a real multi-target incident post-mortem (MARS + OLA permissionless-`sync()`-donation drains, the `0x2524b98f` operator cluster). Each item is grounded in concrete friction from that investigation. Reuse existing modules (`cache`, `scanners`, `scryer_http` key-pool, the `get_tx`/`asset_transfers` enrichment) — these are mostly new *surfaces* over capabilities already present.

## Thesis

A forensic investigation is **graph traversal + classification + bounded distillation**:
- **money-flow graph** (attacker → hops → cash-out), **deployment tree** (EOA → its CREATE'd contracts), **clone/family graph** (attack contract ↔ spares; victim ↔ template).

Today scryer returns **raw node/edge data**, forcing the agent to walk the graph by hand, re-aggregate at each node, and re-classify addresses it already saw. Every pain point below is this impedance mismatch. The fix is to push **traversal, classification, and bounded output** into the data layer so the agent reasons over a clean graph instead of re-summarizing firehoses.

---

## Ranked work

### 1. Bounded output on `asset_transfers` + `get_tx` — HIGHEST frequency (hit ~5× in one case)
`asset_transfers` on a pool/hub returned 1.6 MB / 80k lines; `get_tx` on a loop-heavy exploit tx returned 104 KB / 2,867 lines. Both got dumped to a file and forced a `Read` of the saved blob — polluting the agent's context with raw data it had to re-summarize. The summary fields are **already computed** (they sit at the top of the saved blob); they're just buried under the full list.
- **`asset_transfers`**: add `summary_only: bool` (return only `count`/`distinct_counterparties`/`first_funder`/`likely_service_hub`/`earliest_block` + the top-`top_n` counterparties by value, default `top_n=25`), and a hard `max_bytes` cap that truncates the counterparty list with a `truncated:true` + `omitted:N` flag rather than overflowing.
- **`get_tx`**: add `net_flows_only: bool` (skip the per-event decode, return `net_flows`/`net_flows_human`/`flow_summary`/`labels` only). A loop-heavy tx has thousands of Transfer events but only a handful of net movers.
- Principle: **a tool must never return more than an agent can read in-context.** If the full data is large, return the distillation + a handle (`"call get_logs/asset_transfers with address=X for detail"`).

### 2. `deployed_by(eoa)` / `operator_profile(eoa)` — HIGHEST value (the missing primitive)
The whole "this attacker is a repeat offender, 5 contracts, 2 confirmed ops" breakthrough required a **hand-rolled CREATE-address enumeration script** (keccak+rlp). This should be native.
- **`deployed_by(eoa, chain=…)`**: for `nonce` in `0..getTransactionCount(eoa)-1`, compute `create_addr = keccak256(rlp([eoa_bytes, nonce]))[12:]`, `eth_getCode` each; return every address with code `{nonce, address, code_size}`. Deterministic, no Etherscan (which is paywalled on BSC/Base). Cap the nonce scan (e.g. 500) with a `truncated` flag.
- **`operator_profile(eoa, chain=…)`** (the graph-level meta-primitive): compose `deployed_by` + per-contract classify (`bytecode_abi`) + per-contract usage (`asset_transfers count>0`?) + funding (`asset_transfers direction=in` summary) + cash-out (`direction=out` summary) → one dossier: `{deployed:[{addr,type,used,victim?}], confirmed_ops, dormant_spares, funding_sources, cash_out, repeat_offender:bool}`. This collapses ~8 calls + a script into one.

### 3. `deployer` creation-tx fallback — fixes a real failure this case
`deployer` could not reverse the creation tx for the attack contracts ("emit no mint/log at deploy") — it relies on the first mint/log at the deploy block, which only exists for tokens.
- After the `eth_getCode` bisect finds the deploy block, **scan that block's txs for `receipt.contractAddress == target`** (direct CREATE) — then `tx.from` is the deployer and `tx.hash` the creation tx, for ANY contract, not just tokens. Keep the factory path (`tx.to != null`).

### 4. `trace_funds(from, max_hops, chain=…)` — graph money-flow, not a dump
Tracing proceeds (attacker → hop → aggregator → bridge → BSC endpoint) was manual, one hop per call, re-reading huge blobs and twice mis-reading a pool as a "service wallet".
- Walk `direction=out` from `from`, following the largest-value edge per hop up to `max_hops`; **classify each node** (EOA / token / pool / router / bridge / CEX / `likely_service_hub`) and **STOP at a service hub / bridge / CEX** (the trail ends there — don't expand a shared hub's thousands of edges). Return a compact path graph `[{from,to,asset,amount,to_type,stop_reason?}]` + `final_destination` + `dead_ends_at_service:bool`. Compose from `asset_transfers` + classification; bound output hard.

### 5. `scan_corpus(pattern)` / `registry_grep` — turn one victim into the family
To find OTHER victims of the `sync()`-donation HYIP template, there is no way to search the crawled verified sources for a vuln signature. The `scanners` module (regex/Slither) has the capability but isn't exposed.
- **`scan_corpus(pattern, chain=…, verified_only=True)`**: grep the registry's crawled `.sol` sources for a regex/AST signature (e.g. an external `sync()` doing `balanceOf(this) → transfer(pair,…) → pair.sync()`), returning matching `{address, source_hash, snippet}`. Reuse `scanners`' rule engine. Caveat to surface in the result: matches only CRAWLED contracts (not the whole chain) — a `coverage` note so the agent calibrates ("N of the crawled corpus", not "N on BSC").
- Also helps the clone gap: bespoke attack contracts don't byte-match, and a refactored victim fork (OLA vs MARS) has a different `source_hash` — a **selector-set / AST-signature** match links them where `registry_clones` can't.

### 6. Address type-classification attached everywhere
`asset_transfers`/`get_tx` `label`s came back `null` for almost everything on BSC (bridges, CEX hubs, pools), and I twice narrated a pool as a wallet. The bytecode is right there.
- For the top-N counterparties (and `get_tx` parties), attach `type` from a cheap `bytecode_abi` classify (EOA / token / univ2-pair / univ3-pool / router / proxy / unknown-contract), cached by code-hash in the `cache` module. This is the deterministic backstop for the thin label DB — and it is exactly what `likely_service_hub` is trying to approximate. (Separately: expand the static label set for BSC/Base — major bridges like Relay solvers, CEX hot wallets, known gambling/HYIP hubs.)

### 7. `trace_tx` / `simulate_tx` — local, free decoded trace (from the earlier spec)
`get_tx` decodes only known events, not the full internal call tree; cracking GPXHooks needed a Foundry `-vvvv` trace. Add a **local** decoded-trace tool (NOT Tenderly):
- **`trace_tx(tx_hash, chain, with_state_diff?)`**: get the call tree via `cast run <tx> --rpc-url <archive> --json` (Foundry/WSL; archive `eth_*` only, robust vs `debug_`/`trace_` gating) with an RPC `debug_traceTransaction{callTracer}` fallback; decode selectors via openchain/4byte (cached) → `bytecode_abi` for unknowns → verified ABI for names. Reuse the chain key-pool; redact the RPC key (b2c7447 pattern). Output: decoded `call_tree` + `events` + `net_flows` + optional `state_diff`, bounded.
- Phase 2 **`simulate_tx`** (unsent tx + state overrides) for exploit pre-flight without a `.t.sol`.

---

## Cross-cutting principles (bake into every forensic tool)
- **Never a firehose:** bound every output; return distillation + a detail handle.
- **Classify at the data layer:** every address carries a `type`; the agent should never have to guess "pool vs wallet".
- **Calibration flags travel with attributions:** extend the `likely_service_hub` philosophy — a service/bridge/CEX counterparty is flagged as a laundering hop, never surfaced as "common owner".
- **Negatives carry a coverage note:** `registry`/`scan_corpus` results say "N of the crawled corpus", so the agent never reads "not found" as "doesn't exist".

## Reuse map
- `cache`: code-hash→type, selector→signature, deployer results.
- `scanners`: `scan_corpus` rule engine.
- `scryer_http` key-pool + archive resolution: `trace_tx`, `deployed_by`, `trace_funds`.
- existing `get_tx`/`asset_transfers` enrichment (`flow_summary`, `likely_service_hub`): extend, don't rebuild.
