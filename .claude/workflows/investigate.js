// investigate — reusable exploit post-mortem for a single tx.
// Usage: Workflow({ name: 'investigate', args: '0x<exploit-tx-hash>' })
//    or: Workflow({ name: 'investigate', args: { tx: '0x...', chain_id: 56 } })
// Produces a verified dossier: victim + root-cause + profit + money-flow + operator profile.
// Encodes the forensic disciplines (classify-before-narrate, positive-control, calibrate,
// bounded reads, CREATE-enumeration) learned from the MARS/OLA investigation.

export const meta = {
  name: 'investigate',
  description: 'Exploit post-mortem for a tx: victim, root-cause, profit, money-flow, operator profile — adversarially verified',
  phases: [
    { title: 'Decode', detail: 'get_tx -> victim / attacker / attack contract / profit' },
    { title: 'Analyze', detail: 'parallel: root-cause (victim), operator profile (attacker EOA), money-flow trace' },
    { title: 'Verify', detail: 'adversarial check of the assembled dossier + calibration flags' },
  ],
}

const TX = (typeof args === 'string' ? args : (args && (args.tx || args.tx_hash))) || ''
const CHAIN = (args && args.chain_id) || 56
if (!TX) throw new Error('investigate: pass the exploit tx hash as args — a string, or { tx, chain_id }. Default chain_id 56 (BSC).')

const DISC = `DISCIPLINE (apply strictly; these prevent the four most common post-mortem errors): ` +
  `(1) CLASSIFY-before-narrate — before calling any address a "wallet/service/launderer/victim", run scryer bytecode_abi on it: a getReserves()/swap()/mint()/token0() surface is a DEX POOL (its balance is the pool reserve, NOT someone's stash); high distinct_counterparties / likely_service_hub = a SERVICE, not a person. ` +
  `(2) VERIFY-before-assert — a negative ("never used / dormant / no clones") needs a POSITIVE CONTROL: run the same query on a KNOWN-active sibling and confirm it returns data before concluding 0 = absence; a genuine negative has no rate_limited flag. ` +
  `(3) CALIBRATE attribution — a shared CEX / bridge / service-hub counterparty is a laundering HOP, never proof of common ownership. ` +
  `(4) BOUNDED reads — query the attacker EOA (low-traffic), not a pool/hub; read summary fields only, never pull a pool's full history into your reasoning.`

const DECODE = { type: 'object', properties: {
  tx: { type: 'string' }, chain_id: { type: 'integer' },
  victim_name: { type: 'string' }, victim_address: { type: 'string' },
  attacker_eoa: { type: 'string' }, attack_contract: { type: 'string' },
  drained_asset: { type: 'string' }, drained_amount_usd: { type: 'string' },
  attacker_profit_usd: { type: 'string' }, block_date: { type: 'string' }, notes: { type: 'string' },
}, required: ['victim_address', 'attacker_eoa', 'notes'] }

const ROOT = { type: 'object', properties: {
  victim: { type: 'string' }, root_cause: { type: 'string' }, file_lines: { type: 'string' },
  broken_invariant: { type: 'string' }, class: { type: 'string' },
  still_exploitable: { type: 'boolean' }, usd_at_risk_now: { type: 'string' },
  other_vulns: { type: 'string' }, confidence: { type: 'string' }, notes: { type: 'string' },
}, required: ['root_cause', 'notes'] }

const OP = { type: 'object', properties: {
  attacker_eoa: { type: 'string' }, deployed_contracts: { type: 'string' },
  confirmed_ops: { type: 'string' }, dormant_or_spare: { type: 'string' },
  repeat_offender: { type: 'boolean' }, funding_sources: { type: 'string' },
  confidence: { type: 'string' }, notes: { type: 'string' },
}, required: ['repeat_offender', 'notes'] }

const MONEY = { type: 'object', properties: {
  path: { type: 'string' }, final_destination: { type: 'string' }, destination_type: { type: 'string' },
  still_static: { type: 'boolean' }, confidence: { type: 'string' }, notes: { type: 'string' },
}, required: ['path', 'notes'] }

const VERIFY = { type: 'object', properties: {
  checks_run: { type: 'string' }, corrections: { type: 'string' },
  calibration_flags: { type: 'string' }, verdict: { type: 'string' }, notes: { type: 'string' },
}, required: ['verdict', 'notes'] }

phase('Decode')
const d = await agent(
  `Decode exploit tx ${TX} on chain_id ${CHAIN} with scryer get_tx — rely on net_flows / flow_summary / labels; do NOT dump the full event list (use net_flows_only semantics: a loop-heavy tx has many events but few net movers). Identify: VICTIM (biggest token/USDT loser from flow_summary), ATTACKER EOA (tx sender / net beneficiary), ATTACK CONTRACT (tx 'to'), the drained asset + USD amount, and the attacker's REALIZED profit in USD. Honor token decimals exactly (do not assume 18). ${DISC}`,
  { label: 'decode', phase: 'Decode', agentType: 'hunter', schema: DECODE }
)

phase('Analyze')
const [root, op, money] = await parallel([
  () => agent(
    `ROOT-CAUSE the victim contract ${d.victim_address} (chain_id ${CHAIN}). scryer download_contract + verify_source, then Read the source. Quote the EXACT function signature + file:line for the bug (verify-gate — no file:line = a LEAD). State the BROKEN INVARIANT, the contract CLASS, whether it is STILL exploitable NOW (live reads: paused? ownership renounced? how much USD at risk right now?), and any OTHER vulns (owner backdoors / honeypot controls / recycle-style). ${DISC}`,
    { label: 'root-cause', phase: 'Analyze', agentType: 'hunter', schema: ROOT }
  ),
  () => agent(
    `OPERATOR PROFILE for attacker EOA ${d.attacker_eoa} (chain_id ${CHAIN}) — is this a repeat offender? ENUMERATE what it DEPLOYED (do NOT rely on registry_clones): for nonce 0..N-1 compute CREATE address keccak256(rlp([eoa_bytes, nonce]))[12:] and eth_getCode each (Bash + eth_hash/Crypto keccak; read an Alchemy BSC archive key from .env — ALCHEMY_KEY_2; build the url yourself, BSC_URL has an unexpanded \${ALCHEMY_KEY}). VERIFY your RLP by confirming the known attack contract ${d.attack_contract} appears at its nonce. For each deployed contract: classify (bytecode_abi), check if EXECUTED (asset_transfers, WITH a positive control = the known attack contract) and against which victim. Trace funding (asset_transfers direction=in, summary only). Decide repeat_offender = (more than one EXECUTED op). Distinguish dormant/spare (0 activity) from confirmed ops. ${DISC}`,
    { label: 'operator', phase: 'Analyze', agentType: 'hunter', schema: OP }
  ),
  () => agent(
    `MONEY-FLOW: trace attacker ${d.attacker_eoa}'s proceeds to the final destination (chain_id ${CHAIN}). scryer asset_transfers direction=out on the EOA (NOT on any pool/hub — that overflows and is meaningless). Follow the largest-value hops until you hit a service hub / bridge / CEX; CLASSIFY each node (bytecode_abi) — a pool/router/token is not a wallet. Report the path, the final destination + its TYPE, and whether the funds are still static there. Remember: a shared hub/bridge is where the trail ENDS, not who the owner is. ${DISC}`,
    { label: 'money-flow', phase: 'Analyze', agentType: 'hunter', schema: MONEY }
  ),
])

phase('Verify')
const v = await agent(
  `Adversarially VERIFY this assembled exploit post-mortem BEFORE it is recorded. Assembled findings:\n` +
  `DECODE: ${JSON.stringify(d)}\nROOT-CAUSE: ${JSON.stringify(root)}\nOPERATOR: ${JSON.stringify(op)}\nMONEY: ${JSON.stringify(money)}\n\n` +
  `Run these checks and report what you find: (a) is any claimed "victim" or "other op" actually a DORMANT / never-executed contract (demand a positive control)? (b) is any "launderer / operator wallet / service" actually a DEX pool or token contract (classify it with bytecode_abi)? (c) does any attribution rest on a shared CEX / bridge / service-hub (the calibration trap)? (d) do the profit / drained numbers reconcile with the decoded net_flows (victim loss >= attacker profit, with the gap explained by fees / slippage / token tax)? ` +
  `Report: checks_run, any CORRECTIONS to the findings, the calibration_flags that MUST accompany the recorded result, and a final verdict (CONFIRMED or the correction). ${DISC}`,
  { label: 'verify', phase: 'Verify', agentType: 'hunter', schema: VERIFY }
)

return { tx: TX, chain_id: CHAIN, decode: d, root_cause: root, operator: op, money_flow: money, verification: v }
