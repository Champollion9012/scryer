# AGENTS.md

Conventions for AI coding agents (and humans) working on Scryer.

## Project layout

Flat module layout at the repo root — **do not** restructure into a `scryer/` package without a coordinated migration; many CLI scripts import siblings directly (`from contract_registry import …`).

Reusable infrastructure modules are prefixed `scryer_`:

- `scryer_config` — env / dotenv loading, single source of truth for runtime settings.
- `scryer_logging` — structured logger; preferred over `print()` in new code.
- `scryer_http` — shared `httpx` client factory (timeouts, retries, SOCKS proxy fallback).

Domain modules (no prefix) are the user-visible CLI entry points:

| Module | Purpose |
|--------|---------|
| `download_contract` | Single-contract source downloader (Sourcify → Blockscout → Etherscan-like → IPFS). |
| `contract_crawler` | Multi-chain bulk crawler. |
| `rpc_contract_discovery` | RPC block scanner + decompile fallback. |
| `contract_registry` | SQLite registry indexed by source hash. |
| `data_sources` | Blockscout / on-chain / BigQuery integrations. |
| `decompilers` | Heimdall (via WSL on Windows) + Panoramix fallback. |
| `bounty_pipeline` | Download + audit driver for a JSON target list. |
| `audit_contracts` | LLM audit pipeline with map-reduce for large codebases. |
| `llm_providers` | OpenAI / Claude / Gemini abstraction. |
| `scanners` | Regex (SWC-aligned) + Slither vulnerability scanner. |
| `similarity` / `similarity_cli` | GraphCodeBERT + ChromaDB clone search. |
| `report_renderer` | Markdown / HTML report rendering. |
| `cache` | Generic on-disk cache helper. |
| `web` | Flask read-only dashboard over the registry. |

## Python

- Target **Python 3.11+** (`.python-version` pins 3.11; CI matrix covers 3.11–3.13).
- All new modules: `from __future__ import annotations` at the top.
- Prefer `pathlib.Path` over `os.path`.
- Type hints required for all new public functions; use `Iterable`, `Mapping`, `Sequence` from `collections.abc`.
- For async code, use `asyncio.gather` with explicit concurrency caps; never unbounded.

## Logging

In **new code** prefer `scryer_logging.get_logger(__name__)` instead of `print()`. Keep CLI user-facing output (final results, summaries) on `print()` if that is what the user expects to see; route everything else through the logger.

## HTTP

In **new code** use `scryer_http.async_client()` / `scryer_http.sync_client()` instead of constructing `httpx.AsyncClient(...)` directly. This gets you timeouts, retries, and the SOCKS-proxy fallback for free.

## Configuration

Env vars are loaded once via `scryer_config.load()` (idempotent — safe to call multiple times). Look up values via `scryer_config.get("OPENAI_API_KEY")` or directly via `os.getenv` after `load()` has run. **Do not** call `load_dotenv` directly in new modules.

## Tooling

```bash
pip install -e ".[dev]"          # editable install + dev extras
ruff check .                     # lint
ruff format .                    # format
mypy .                           # type check (incremental — see pyproject.toml)
pytest                           # run Python tests
pytest --cov=. --cov-report=term # with coverage
```

CI runs `ruff check`, `mypy`, and `pytest` on Python 3.11 / 3.12 / 3.13. Network-marked tests (`@pytest.mark.network`) and slow tests are excluded by default.

## Tests

- Python tests live under `tests/python/` and use `pytest`.
- Foundry exploit PoCs live under `tests/*.t.sol` — those are run with `forge test`, **not** pytest.
- Tests must not hit the network unless marked `@pytest.mark.network`.
- Use temp dirs (`tmp_path` fixture) — never write to repo paths during tests.

## Commit hygiene

- One logical change per commit.
- Conventional-commits-ish prefix encouraged: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`.
- Do **not** commit generated artefacts (`sources/`, `audit_reports/`, `runs/`, `decompiled/`, `.contract_registry.db`, `.similarity_db/`, `out/`, `cache/`, `lib/`).

## Secrets

- Never commit `.env`, API keys, or downloaded source caches.
- Tests must not require real API keys — stub `httpx` / use fake providers.

## Platform notes

- `decompilers.py` shells out to Heimdall via **WSL** on Windows. Provide `HEIMDALL_PATH` in `.env`.
- Foundry tests in `tests/*.t.sol` likewise expect `forge` available (locally or in WSL).
- Similarity stack (`torch` / `sentence-transformers` / `chromadb`) is heavy — only install when needed (`pip install -e ".[similarity]"`).
