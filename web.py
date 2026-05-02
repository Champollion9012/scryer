"""
Contract Registry Web Interface.
A dark-themed web UI for querying and exploring crawled contracts.
"""

from pathlib import Path

from flask import Flask, jsonify, render_template, request

import scryer_config
from contract_registry import ContractRegistry
from scryer_logging import get_logger

_log = get_logger(__name__)

app = Flask(__name__)
registry = ContractRegistry()


# ============================================================================
# Helpers
# ============================================================================

CHAIN_NAMES = {
    1: "Ethereum",
    56: "BSC",
    137: "Polygon",
    42161: "Arbitrum",
    10: "Optimism",
    8453: "Base",
    43114: "Avalanche",
    250: "Fantom",
}

CHAIN_EXPLORERS = {
    1: "https://etherscan.io",
    56: "https://bscscan.com",
    137: "https://polygonscan.com",
    42161: "https://arbiscan.io",
    10: "https://optimistic.etherscan.io",
    8453: "https://basescan.org",
    43114: "https://snowtrace.io",
    250: "https://ftmscan.com",
}


def get_recent_contracts(limit: int = 20) -> list[dict]:
    """Get recent contracts from registry."""
    import sqlite3

    conn = sqlite3.connect(registry.db_path)
    try:
        cursor = conn.execute(
            """
            SELECT chain_id, address, contract_name, source_hash, crawled_at, compiler_version
            FROM contracts
            ORDER BY crawled_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [
            {
                "chain_id": row[0],
                "chain_name": CHAIN_NAMES.get(row[0], str(row[0])),
                "address": row[1],
                "contract_name": row[2],
                "source_hash": row[3],
                "crawled_at": row[4],
                "compiler_version": row[5],
            }
            for row in cursor.fetchall()
        ]
    finally:
        conn.close()


def search_contracts(query: str = "", chain: str | None = None, limit: int = 100) -> list[dict]:
    """Search contracts by address or name."""
    import sqlite3

    conn = sqlite3.connect(registry.db_path)
    try:
        sql = """
            SELECT chain_id, address, contract_name, source_hash, compiler_version
            FROM contracts
            WHERE 1=1
        """
        params: list = []

        if query:
            sql += " AND (address LIKE ? OR contract_name LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])

        if chain:
            sql += " AND chain_id = ?"
            params.append(int(chain))

        sql += " ORDER BY crawled_at DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(sql, params)
        return [
            {
                "chain_id": row[0],
                "chain_name": CHAIN_NAMES.get(row[0], str(row[0])),
                "address": row[1],
                "contract_name": row[2],
                "source_hash": row[3],
                "compiler_version": row[4],
            }
            for row in cursor.fetchall()
        ]
    finally:
        conn.close()


# ============================================================================
# Page Routes
# ============================================================================


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        page="home",
        stats=registry.stats(),
        recent=get_recent_contracts(20),
    )


@app.route("/contracts")
def contracts():
    query = request.args.get("q", "")
    chain = request.args.get("chain", "")
    return render_template(
        "contracts.html",
        page="contracts",
        contracts=search_contracts(query, chain or None),
        query=query,
        chain=chain,
    )


@app.route("/duplicates")
def duplicates():
    return render_template(
        "duplicates.html",
        page="duplicates",
        duplicates=registry.get_top_duplicates(50),
    )


@app.route("/hash/<source_hash>")
def hash_detail(source_hash):
    contracts_for_hash = registry.get_addresses_by_hash(source_hash)
    chains = list({c["chain_id"] for c in contracts_for_hash})
    return render_template(
        "hash_detail.html",
        page="duplicates",
        source_hash=source_hash,
        contracts=contracts_for_hash,
        chains=chains,
    )


@app.route("/search")
def search():
    address = request.args.get("address", "")
    chain = request.args.get("chain", "56")
    related = registry.find_related_contracts(int(chain), address) if address else []
    return render_template(
        "search.html",
        page="search",
        address=address,
        chain=chain,
        related=related,
    )


@app.route("/contract/<int:chain_id>/<address>")
def contract_detail(chain_id, address):
    """View a specific contract and its source files."""
    source_hash = registry.get_hash_by_address(chain_id, address)
    related = registry.find_related_contracts(chain_id, address)

    sources_dir = Path("sources") / f"{chain_id}_{address.lower()}"
    source_files: dict[str, str] = {}
    if sources_dir.exists():
        for f in sources_dir.glob("*.sol"):
            source_files[f.name] = f.read_text(encoding="utf-8", errors="ignore")

    explorer_url = f"{CHAIN_EXPLORERS.get(chain_id, 'https://bscscan.com')}/address/{address}"
    return render_template(
        "contract_detail.html",
        page="contracts",
        chain_id=chain_id,
        chain_name=CHAIN_NAMES.get(chain_id, str(chain_id)),
        address=address,
        source_hash=source_hash,
        related=related,
        source_files=source_files,
        explorer_url=explorer_url,
    )


@app.route("/vulnerabilities")
def vulnerabilities():
    """View vulnerability tags."""
    import sqlite3

    conn = sqlite3.connect(registry.db_path)
    try:
        cursor = conn.execute("""
            SELECT v.tag, v.severity, v.description, v.source_hash,
                   (SELECT COUNT(*) FROM contracts c WHERE c.source_hash = v.source_hash) as affected
            FROM vulnerability_tags v
            ORDER BY v.created_at DESC
        """)
        vulns = [
            {
                "tag": row[0],
                "severity": row[1],
                "description": row[2],
                "source_hash": row[3],
                "affected": row[4],
            }
            for row in cursor.fetchall()
        ]
    finally:
        conn.close()

    return render_template("vulnerabilities.html", page="vulns", vulns=vulns)


@app.route("/similarity", methods=["GET", "POST"])
def similarity_search():
    """Similarity search page."""
    code = ""
    address = ""
    chain = "56"
    results: list[dict] = []
    searched = False
    min_sim = 0.7
    top_n = 10
    error = None
    index_stats = {"total_contracts": 0}

    try:
        from similarity import SimilarityIndex

        index = SimilarityIndex()
        index_stats = index.stats()
    except Exception:
        pass

    if request.method == "POST":
        address = request.form.get("address", "").strip()
        chain = request.form.get("chain", "56")
        code = request.form.get("code", "").strip()
        min_sim = float(request.form.get("min_sim", 0.7))
        top_n = int(request.form.get("top_n", 10))
        searched = True

        if address and address.startswith("0x"):
            chain_id = int(chain)
            sources_dir = Path("sources") / f"{chain_id}_{address.lower()}"
            if sources_dir.exists():
                sol_files = list(sources_dir.glob("*.sol"))
                if sol_files:
                    code = sol_files[0].read_text(encoding="utf-8", errors="ignore")

            if not code:
                try:
                    import asyncio

                    import scryer_http
                    from contract_crawler import AsyncRateLimiter, fetch_sourcify_source

                    async def fetch_code():
                        async with scryer_http.async_client() as client:
                            rate_limiter = AsyncRateLimiter(3.0)
                            sources, _ = await fetch_sourcify_source(chain_id, address, client, rate_limiter)
                            return sources

                    sources = asyncio.run(fetch_code())
                    if sources:
                        code = next(iter(sources.values()))
                except Exception as e:
                    error = f"Could not fetch code for {address}: {e}"

        if code:
            try:
                from similarity import SimilarityIndex

                index = SimilarityIndex()
                results = index.find_similar(code, n_results=top_n, min_similarity=min_sim)
            except Exception as e:
                error = f"Similarity search error: {e}"
        elif not error:
            error = "Please provide either a contract address or paste code"

    return render_template(
        "similarity.html",
        page="similarity",
        code=code,
        address=address,
        chain=chain,
        results=results,
        searched=searched,
        min_sim=min_sim,
        top_n=top_n,
        error=error,
        index_stats=index_stats,
    )


# ============================================================================
# API Routes
# ============================================================================


@app.route("/api/tag-vulnerability", methods=["POST"])
def api_tag_vulnerability():
    """Add vulnerability tag via form."""
    source_hash = request.form.get("source_hash", "")
    tag = request.form.get("tag", "")
    severity = request.form.get("severity", "Medium")

    if source_hash and tag:
        affected = registry.tag_vulnerability(source_hash, tag, severity)
        return jsonify({"success": True, "affected": affected})
    return jsonify({"success": False, "error": "Missing fields"})


@app.route("/api/stats")
def api_stats():
    return jsonify(registry.stats())


@app.route("/api/contracts")
def api_contracts():
    chain = request.args.get("chain")
    limit = int(request.args.get("limit", 100))
    return jsonify(search_contracts(chain=chain, limit=limit))


@app.route("/api/related/<int:chain_id>/<address>")
def api_related(chain_id, address):
    return jsonify(registry.find_related_contracts(chain_id, address))


@app.route("/api/export/<format>")
def api_export(format):
    """Export contracts data."""
    rows = search_contracts(limit=10000)

    if format == "json":
        return jsonify(rows)
    if format == "csv":
        import csv
        from io import StringIO

        output = StringIO()
        # search_contracts returns extra fields (chain_name, compiler_version);
        # extrasaction="ignore" drops them so we keep CSV columns stable.
        writer = csv.DictWriter(
            output,
            fieldnames=["chain_id", "address", "contract_name", "source_hash"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
        return (
            output.getvalue(),
            200,
            {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=contracts.csv"},
        )

    return jsonify({"error": "Unsupported format"})


@app.route("/api/similarity", methods=["POST"])
def api_similarity():
    """API endpoint for similarity search."""
    data = request.get_json() or {}
    code = data.get("code", "")
    min_sim = float(data.get("min_similarity", 0.7))
    top_n = int(data.get("top_n", 10))

    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    try:
        from similarity import SimilarityIndex

        index = SimilarityIndex()
        results = index.find_similar(code, n_results=top_n, min_similarity=min_sim)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def main() -> None:
    """CLI entry point for the Flask dashboard.

    Debug mode is gated behind ``FLASK_DEBUG`` env var (default off).
    Werkzeug's debugger exposes a PIN-protected REPL that has been the source
    of real-world RCEs when accidentally left on in production.
    """
    scryer_config.load()
    debug = scryer_config.get_bool("FLASK_DEBUG", False)
    port = scryer_config.get_int("FLASK_PORT", 5000) or 5000
    _log.info("Starting Contract Registry Web Interface (debug=%s)...", debug)
    _log.info("Open http://localhost:%d in your browser", port)
    app.run(debug=debug, port=port)


if __name__ == "__main__":
    main()
