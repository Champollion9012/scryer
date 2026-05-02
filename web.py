"""
Contract Registry Web Interface.
A dark-themed web UI for querying and exploring crawled contracts.
"""

from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from contract_registry import ContractRegistry
from scryer_logging import get_logger

_log = get_logger(__name__)

app = Flask(__name__)
registry = ContractRegistry()

# ============================================================================
# HTML Templates
# ============================================================================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contract Registry Explorer</title>
    <!-- Prism.js for syntax highlighting -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-solidity.min.js"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-hover: #21262d;
            --border: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --accent-secondary: #a371f7;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
            --gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-bottom: 1px solid var(--border);
            padding: 20px 0;
            margin-bottom: 30px;
        }
        
        header h1 {
            font-size: 1.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        header h1::before {
            content: '📦';
            font-size: 1.3rem;
            -webkit-text-fill-color: initial;
        }
        
        nav {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        nav a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: all 0.2s;
            border: 1px solid transparent;
        }
        
        nav a:hover {
            background: var(--bg-hover);
            color: var(--accent);
            border-color: var(--border);
        }
        
        nav a.active {
            background: var(--accent);
            color: white;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }
        
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .search-box {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
        }
        
        .search-box input, .search-box select {
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            padding: 12px 16px;
            font-size: 1rem;
            width: 100%;
            margin-bottom: 15px;
            transition: border-color 0.2s;
        }
        
        .search-box input:focus, .search-box select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
        }
        
        .search-box button, .btn {
            background: var(--gradient);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            font-size: 1rem;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.2s;
            font-weight: 500;
        }
        
        .search-box button:hover, .btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: var(--bg-hover);
            border: 1px solid var(--border);
        }
        
        .btn-danger {
            background: var(--danger);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.85rem;
        }
        
        .search-row {
            display: grid;
            grid-template-columns: 1fr 150px 120px;
            gap: 15px;
            align-items: end;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
        }
        
        th, td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--bg-hover);
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tr {
            transition: background 0.2s;
        }
        
        tr:hover {
            background: var(--bg-hover);
        }
        
        .address {
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.9rem;
            color: var(--accent);
            cursor: pointer;
        }
        
        .address:hover {
            text-decoration: underline;
        }
        
        .hash {
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        .chain-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .chain-1 { background: #627eea22; color: #627eea; border: 1px solid #627eea44; }
        .chain-56 { background: #f0b90b22; color: #f0b90b; border: 1px solid #f0b90b44; }
        .chain-137 { background: #8247e522; color: #8247e5; border: 1px solid #8247e544; }
        .chain-42161 { background: #28a0f022; color: #28a0f0; border: 1px solid #28a0f044; }
        .chain-10 { background: #ff042022; color: #ff0420; border: 1px solid #ff042044; }
        .chain-8453 { background: #0052ff22; color: #0052ff; border: 1px solid #0052ff44; }
        
        .count-badge {
            background: var(--success);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .vuln-badge {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .vuln-high { background: #f8514922; color: #f85149; }
        .vuln-medium { background: #d2992222; color: #d29922; }
        .vuln-low { background: #3fb95022; color: #3fb950; }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }
        
        .empty-state p {
            font-size: 1.1rem;
            margin-bottom: 15px;
        }
        
        .source-viewer {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-top: 20px;
            overflow: hidden;
        }
        
        .source-viewer header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: var(--bg-hover);
            border-bottom: 1px solid var(--border);
            margin-bottom: 0;
        }
        
        .source-viewer h4 {
            font-size: 0.9rem;
            color: var(--text-primary);
        }
        
        .source-viewer pre {
            margin: 0;
            padding: 20px;
            overflow-x: auto;
            font-size: 0.85rem;
            max-height: 500px;
            overflow-y: auto;
            background: #1e1e1e !important;
        }
        
        .source-viewer code {
            font-family: 'SF Mono', Consolas, 'Fira Code', monospace;
        }
        
        .chart-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .pagination {
            display: flex;
            gap: 8px;
            justify-content: center;
            margin-top: 20px;
        }
        
        .pagination a {
            padding: 8px 14px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .pagination a:hover, .pagination a.active {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }
        
        .tag-form {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            align-items: center;
        }
        
        .tag-form input {
            flex: 1;
            padding: 10px 14px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
        }
        
        .tooltip {
            position: relative;
        }
        
        .tooltip::after {
            content: 'Click to copy';
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            padding: 4px 8px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-size: 0.75rem;
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none;
        }
        
        .tooltip:hover::after {
            opacity: 1;
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 20px;
            background: var(--success);
            color: white;
            border-radius: 8px;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s;
            z-index: 1000;
        }
        
        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .search-row {
                grid-template-columns: 1fr;
            }
            nav {
                gap: 5px;
            }
            nav a {
                padding: 6px 12px;
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Contract Registry Explorer</h1>
            <nav>
                <a href="/" class="{{ 'active' if page == 'home' else '' }}">Dashboard</a>
                <a href="/contracts" class="{{ 'active' if page == 'contracts' else '' }}">Contracts</a>
                <a href="/duplicates" class="{{ 'active' if page == 'duplicates' else '' }}">Duplicates</a>
                <a href="/search" class="{{ 'active' if page == 'search' else '' }}">Search</a>
                <a href="/similarity" class="{{ 'active' if page == 'similarity' else '' }}">Similarity</a>
                <a href="/vulnerabilities" class="{{ 'active' if page == 'vulns' else '' }}">Vulnerabilities</a>
            </nav>
        </div>
    </header>
    
    <main class="container">
        {{ content | safe }}
    </main>
    
    <div id="toast" class="toast"></div>
    
    <footer>
        Contract Registry v2.0 • Powered by Sourcify + Blockscout
    </footer>
    
    <script>
        // Copy to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('Copied to clipboard!');
            });
        }
        
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }
        
        // Make addresses clickable to copy
        document.querySelectorAll('.address').forEach(el => {
            el.addEventListener('click', (e) => {
                if (!e.target.href) {
                    copyToClipboard(el.textContent);
                }
            });
        });
        
        // Initialize Prism
        if (typeof Prism !== 'undefined') {
            Prism.highlightAll();
        }
    </script>
</body>
</html>
"""

DASHBOARD_CONTENT = """
<div class="stats-grid">
    <div class="stat-card">
        <div class="value">{{ stats.total_contracts }}</div>
        <div class="label">Total Contracts</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ stats.unique_source_hashes }}</div>
        <div class="label">Unique Codebases</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ stats.duplicated_hashes }}</div>
        <div class="label">Duplicated Hashes</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ stats.vulnerability_tags }}</div>
        <div class="label">Vulnerability Tags</div>
    </div>
</div>

<h2 style="margin-bottom: 20px; color: var(--text-secondary);">Recent Contracts</h2>
<table>
    <thead>
        <tr>
            <th>Chain</th>
            <th>Address</th>
            <th>Contract Name</th>
            <th>Source Hash</th>
            <th>Crawled At</th>
        </tr>
    </thead>
    <tbody>
        {% for c in recent %}
        <tr>
            <td><span class="chain-badge chain-{{ c.chain_id }}">{{ c.chain_name }}</span></td>
            <td><a href="/contract/{{ c.chain_id }}/{{ c.address }}" class="address">{{ c.address[:10] }}...{{ c.address[-8:] }}</a></td>
            <td>{{ c.contract_name or '-' }}</td>
            <td class="hash">{{ c.source_hash[:16] }}...</td>
            <td>{{ c.crawled_at[:10] if c.crawled_at else '-' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
"""

CONTRACTS_CONTENT = """
<div class="search-box">
    <form method="GET">
        <div class="search-row">
            <input type="text" name="q" placeholder="Search by address or contract name..." value="{{ query }}">
            <select name="chain">
                <option value="">All Chains</option>
                <option value="1" {{ 'selected' if chain == '1' else '' }}>Ethereum</option>
                <option value="56" {{ 'selected' if chain == '56' else '' }}>BSC</option>
                <option value="137" {{ 'selected' if chain == '137' else '' }}>Polygon</option>
                <option value="42161" {{ 'selected' if chain == '42161' else '' }}>Arbitrum</option>
                <option value="10" {{ 'selected' if chain == '10' else '' }}>Optimism</option>
                <option value="8453" {{ 'selected' if chain == '8453' else '' }}>Base</option>
            </select>
            <button type="submit">Search</button>
        </div>
    </form>
</div>

{% if contracts %}
<table>
    <thead>
        <tr>
            <th>Chain</th>
            <th>Address</th>
            <th>Contract Name</th>
            <th>Compiler</th>
            <th>Source Hash</th>
        </tr>
    </thead>
    <tbody>
        {% for c in contracts %}
        <tr>
            <td><span class="chain-badge chain-{{ c.chain_id }}">{{ c.chain_name }}</span></td>
            <td><a href="/contract/{{ c.chain_id }}/{{ c.address }}" class="address">{{ c.address[:10] }}...{{ c.address[-8:] }}</a></td>
            <td>{{ c.contract_name or '-' }}</td>
            <td class="hash">{{ c.compiler_version[:15] if c.compiler_version else '-' }}</td>
            <td class="hash">{{ c.source_hash[:16] }}...</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<div class="empty-state">
    <p>No contracts found</p>
</div>
{% endif %}
"""

DUPLICATES_CONTENT = """
<h2 style="margin-bottom: 20px; color: var(--text-secondary);">Top Duplicated Codebases</h2>
<p style="color: var(--text-secondary); margin-bottom: 20px;">
    These source code patterns appear in multiple contracts. Click to see all instances.
</p>

<table>
    <thead>
        <tr>
            <th>Count</th>
            <th>Sample Name</th>
            <th>Source Hash</th>
            <th>Chains</th>
            <th>First Seen</th>
        </tr>
    </thead>
    <tbody>
        {% for d in duplicates %}
        <tr>
            <td><span class="count-badge">{{ d.contract_count }}x</span></td>
            <td><a href="/hash/{{ d.source_hash }}" style="color: var(--accent);">{{ d.sample_name or 'Unknown' }}</a></td>
            <td class="hash">{{ d.source_hash[:16] }}...</td>
            <td>
                {% for chain in d.chains %}
                <span class="chain-badge chain-{{ chain }}">{{ chain }}</span>
                {% endfor %}
            </td>
            <td>{{ d.first_seen[:10] if d.first_seen else '-' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
"""

HASH_DETAIL_CONTENT = """
<h2 style="margin-bottom: 20px;">
    Contracts with hash: <span class="hash">{{ source_hash[:24] }}...</span>
</h2>

<div class="stats-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom: 30px;">
    <div class="stat-card">
        <div class="value">{{ contracts | length }}</div>
        <div class="label">Total Instances</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ chains | length }}</div>
        <div class="label">Chains</div>
    </div>
</div>

<table>
    <thead>
        <tr>
            <th>Chain</th>
            <th>Address</th>
            <th>Contract Name</th>
            <th>Compiler</th>
            <th>Crawled At</th>
        </tr>
    </thead>
    <tbody>
        {% for c in contracts %}
        <tr>
            <td><span class="chain-badge chain-{{ c.chain_id }}">{{ c.chain_id }}</span></td>
            <td><a href="/contract/{{ c.chain_id }}/{{ c.address }}" class="address">{{ c.address }}</a></td>
            <td>{{ c.contract_name or '-' }}</td>
            <td class="hash">{{ c.compiler_version or '-' }}</td>
            <td>{{ c.crawled_at[:10] if c.crawled_at else '-' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
"""

SEARCH_CONTENT = """
<div class="search-box">
    <h3 style="margin-bottom: 15px;">Find Related Contracts</h3>
    <p style="color: var(--text-secondary); margin-bottom: 20px;">
        Enter a contract address to find all contracts with the same source code.
    </p>
    <form method="GET">
        <div class="search-row">
            <input type="text" name="address" placeholder="0x..." value="{{ address }}">
            <select name="chain">
                <option value="1" {{ 'selected' if chain == '1' else '' }}>Ethereum</option>
                <option value="56" {{ 'selected' if chain == '56' else '' }}>BSC</option>
                <option value="137" {{ 'selected' if chain == '137' else '' }}>Polygon</option>
                <option value="42161" {{ 'selected' if chain == '42161' else '' }}>Arbitrum</option>
            </select>
            <button type="submit">Find Related</button>
        </div>
    </form>
</div>

{% if related %}
<h3 style="margin-bottom: 20px;">Found {{ related | length }} related contracts</h3>
<table>
    <thead>
        <tr>
            <th>Chain</th>
            <th>Address</th>
            <th>Contract Name</th>
        </tr>
    </thead>
    <tbody>
        {% for c in related %}
        <tr>
            <td><span class="chain-badge chain-{{ c.chain_id }}">{{ c.chain_id }}</span></td>
            <td class="address">{{ c.address }}</td>
            <td>{{ c.contract_name or '-' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% elif address %}
<div class="empty-state">
    <p>No related contracts found</p>
</div>
{% endif %}
"""

# ============================================================================
# Routes
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


def get_recent_contracts(limit=20):
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
        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "chain_id": row[0],
                    "chain_name": CHAIN_NAMES.get(row[0], str(row[0])),
                    "address": row[1],
                    "contract_name": row[2],
                    "source_hash": row[3],
                    "crawled_at": row[4],
                    "compiler_version": row[5],
                }
            )
        return results
    finally:
        conn.close()


def search_contracts(query="", chain=None, limit=100):
    """Search contracts by address or name."""
    import sqlite3

    conn = sqlite3.connect(registry.db_path)
    try:
        sql = """
            SELECT chain_id, address, contract_name, source_hash, compiler_version
            FROM contracts
            WHERE 1=1
        """
        params = []

        if query:
            sql += " AND (address LIKE ? OR contract_name LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])

        if chain:
            sql += " AND chain_id = ?"
            params.append(int(chain))

        sql += " ORDER BY crawled_at DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(sql, params)
        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "chain_id": row[0],
                    "chain_name": CHAIN_NAMES.get(row[0], str(row[0])),
                    "address": row[1],
                    "contract_name": row[2],
                    "source_hash": row[3],
                    "compiler_version": row[4],
                }
            )
        return results
    finally:
        conn.close()


@app.route("/")
def dashboard():
    stats = registry.stats()
    recent = get_recent_contracts(20)
    content = render_template_string(DASHBOARD_CONTENT, stats=stats, recent=recent)
    return render_template_string(BASE_TEMPLATE, content=content, page="home")


@app.route("/contracts")
def contracts():
    query = request.args.get("q", "")
    chain = request.args.get("chain", "")
    results = search_contracts(query, chain if chain else None)
    content = render_template_string(CONTRACTS_CONTENT, contracts=results, query=query, chain=chain)
    return render_template_string(BASE_TEMPLATE, content=content, page="contracts")


@app.route("/duplicates")
def duplicates():
    dups = registry.get_top_duplicates(50)
    content = render_template_string(DUPLICATES_CONTENT, duplicates=dups)
    return render_template_string(BASE_TEMPLATE, content=content, page="duplicates")


@app.route("/hash/<source_hash>")
def hash_detail(source_hash):
    contracts = registry.get_addresses_by_hash(source_hash)
    chains = list(set(c["chain_id"] for c in contracts))
    content = render_template_string(HASH_DETAIL_CONTENT, source_hash=source_hash, contracts=contracts, chains=chains)
    return render_template_string(BASE_TEMPLATE, content=content, page="duplicates")


@app.route("/search")
def search():
    address = request.args.get("address", "")
    chain = request.args.get("chain", "56")
    related = []

    if address:
        related = registry.find_related_contracts(int(chain), address)

    content = render_template_string(SEARCH_CONTENT, address=address, chain=chain, related=related)
    return render_template_string(BASE_TEMPLATE, content=content, page="search")


@app.route("/contract/<int:chain_id>/<address>")
def contract_detail(chain_id, address):
    """View a specific contract and its source files."""
    source_hash = registry.get_hash_by_address(chain_id, address)
    related = registry.find_related_contracts(chain_id, address)

    # Load source files from disk
    sources_dir = Path("sources") / f"{chain_id}_{address.lower()}"
    source_files = {}
    if sources_dir.exists():
        for f in sources_dir.glob("*.sol"):
            source_files[f.name] = f.read_text(encoding="utf-8", errors="ignore")

    # Build source files HTML with proper syntax highlighting
    source_html = ""
    for name, src in source_files.items():
        escaped = src.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:8000]
        source_html += f"""
        <div class="source-viewer">
            <header>
                <h4>{name}</h4>
                <button class="btn btn-sm btn-secondary" onclick="copyToClipboard(document.getElementById('src-{name.replace(".", "-")}').textContent)">Copy</button>
            </header>
            <pre><code id="src-{name.replace(".", "-")}" class="language-solidity">{escaped}</code></pre>
        </div>
        """

    # Explorer URL
    explorer_base = CHAIN_EXPLORERS.get(chain_id, "https://bscscan.com")  # Default to BSC if unknown
    if chain_id == 1:
        explorer_base = "https://etherscan.io"
    elif chain_id == 137:
        explorer_base = "https://polygonscan.com"
    elif chain_id == 42161:
        explorer_base = "https://arbiscan.io"
    elif chain_id == 10:
        explorer_base = "https://optimistic.etherscan.io"
    elif chain_id == 8453:
        explorer_base = "https://basescan.org"
    elif chain_id == 43114:
        explorer_base = "https://snowtrace.io"
    elif chain_id == 250:
        explorer_base = "https://ftmscan.com"

    explorer_url = f"{explorer_base}/address/{address}"

    content = f"""
    <h2 style="margin-bottom: 10px;">Contract Details</h2>
    <p style="color: var(--text-secondary); margin-bottom: 20px;">
        <span class="chain-badge chain-{chain_id}">{CHAIN_NAMES.get(chain_id, chain_id)}</span>
        <span class="address tooltip" style="margin-left: 10px;" onclick="copyToClipboard('{address}')">{address}</span>
        <a href="{explorer_url}" target="_blank" class="btn btn-sm btn-secondary" style="margin-left: 10px;">View on Explorer</a>
    </p>
    
    <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 30px;">
        <div class="stat-card">
            <div class="value">{len(related)}</div>
            <div class="label">Related Contracts</div>
        </div>
        <div class="stat-card">
            <div class="value">{len(source_files)}</div>
            <div class="label">Source Files</div>
        </div>
        <div class="stat-card">
            <div class="value">{source_hash[:8] if source_hash else "N/A"}...</div>
            <div class="label">Source Hash</div>
        </div>
    </div>
    
    {'<h3 style="margin-bottom: 15px;">Source Files</h3>' if source_files else '<div class="empty-state"><p>Source files not found locally</p></div>'}
    {source_html}
    """

    return render_template_string(BASE_TEMPLATE, content=content, page="contracts")


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

    content = """
    <h2 style="margin-bottom: 20px;">Vulnerability Tags</h2>
    <p style="color: var(--text-secondary); margin-bottom: 20px;">
        Tag source hashes with known vulnerabilities to track affected contracts.
    </p>
    
    <div class="search-box">
        <form method="POST" action="/api/tag-vulnerability">
            <h4 style="margin-bottom: 15px;">Add New Tag</h4>
            <div class="search-row" style="grid-template-columns: 1fr 1fr 150px 120px;">
                <input type="text" name="source_hash" placeholder="Source Hash" required>
                <input type="text" name="tag" placeholder="Tag (e.g., reentrancy)" required>
                <select name="severity">
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <button type="submit">Add Tag</button>
            </div>
        </form>
    </div>
    
    {% if vulns %}
    <table>
        <thead>
            <tr>
                <th>Tag</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Affected</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for v in vulns %}
            <tr>
                <td><strong>{{ v.tag }}</strong></td>
                <td><span class="vuln-badge vuln-{{ v.severity.lower() }}">{{ v.severity }}</span></td>
                <td>{{ v.description or '-' }}</td>
                <td><a href="/hash/{{ v.source_hash }}">{{ v.affected }} contracts</a></td>
                <td><a href="/hash/{{ v.source_hash }}" class="btn btn-sm btn-secondary">View</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">
        <p>No vulnerability tags yet</p>
    </div>
    {% endif %}
    """

    return render_template_string(BASE_TEMPLATE, content=render_template_string(content, vulns=vulns), page="vulns")


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


# API endpoints
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
    contracts = search_contracts(limit=10000)

    if format == "json":
        return jsonify(contracts)
    if format == "csv":
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=["chain_id", "address", "contract_name", "source_hash"])
        writer.writeheader()
        writer.writerows(contracts)
        return (
            output.getvalue(),
            200,
            {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=contracts.csv"},
        )

    return jsonify({"error": "Unsupported format"})


# ============================================================================
# Similarity Search
# ============================================================================

SIMILARITY_CONTENT = """
<h2 style="margin-bottom: 20px;">Code Similarity Search</h2>
<p style="color: var(--text-secondary); margin-bottom: 20px;">
    Paste Solidity code OR enter a contract address to find similar contracts. Uses CodeBERT embeddings.
</p>

<div class="search-box">
    <form method="POST" action="/similarity">
        <div style="display: grid; grid-template-columns: 150px 1fr 150px; gap: 15px; margin-bottom: 15px; align-items: center;">
            <label style="color: var(--text-secondary);">Contract Address:</label>
            <input type="text" name="address" value="{{ address }}" placeholder="0x... (optional - will fetch code automatically)" style="background: var(--bg-dark); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); padding: 12px 16px;">
            <select name="chain" style="background: var(--bg-dark); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); padding: 12px;">
                <option value="56" {{ 'selected' if chain == '56' else '' }}>BSC</option>
                <option value="1" {{ 'selected' if chain == '1' else '' }}>Ethereum</option>
                <option value="137" {{ 'selected' if chain == '137' else '' }}>Polygon</option>
                <option value="42161" {{ 'selected' if chain == '42161' else '' }}>Arbitrum</option>
            </select>
        </div>
        
        <p style="color: var(--text-secondary); margin-bottom: 10px; font-size: 0.9rem;">Or paste code directly:</p>
        <textarea name="code" rows="10" style="width: 100%; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); padding: 16px; font-family: 'SF Mono', Consolas, monospace; font-size: 0.9rem; resize: vertical;" placeholder="// Paste Solidity code here...">{{ code }}</textarea>
        
        <div style="display: flex; gap: 15px; margin-top: 15px; align-items: center;">
            <button type="submit">Find Similar Contracts</button>
            <label style="color: var(--text-secondary);">
                Min Similarity: 
                <input type="number" name="min_sim" value="{{ min_sim or 0.7 }}" min="0" max="1" step="0.05" style="width: 80px; padding: 8px; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary);">
            </label>
            <label style="color: var(--text-secondary);">
                Max Results: 
                <input type="number" name="top_n" value="{{ top_n or 10 }}" min="1" max="50" style="width: 80px; padding: 8px; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary);">
            </label>
        </div>
    </form>
</div>

{% if error %}
<div style="background: #f8514922; border: 1px solid #f85149; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
    <strong style="color: #f85149;">Error:</strong> {{ error }}
</div>
{% endif %}

{% if results %}
<h3 style="margin-bottom: 15px;">Found {{ results | length }} similar contracts</h3>
<table>
    <thead>
        <tr>
            <th>Similarity</th>
            <th>Contract</th>
            <th>File</th>
            <th>Code Length</th>
        </tr>
    </thead>
    <tbody>
        {% for r in results %}
        <tr>
            <td>
                <span style="display: inline-block; width: 60px; background: linear-gradient(90deg, var(--success) {{ (r.similarity * 100)|int }}%, var(--bg-dark) {{ (r.similarity * 100)|int }}%); padding: 4px 8px; border-radius: 4px; font-weight: 600;">
                    {{ (r.similarity * 100)|round(1) }}%
                </span>
            </td>
            <td class="address">{{ r.id[:50] }}{{ '...' if r.id|length > 50 else '' }}</td>
            <td>{{ r.metadata.filename if r.metadata else '-' }}</td>
            <td>{{ r.metadata.code_length if r.metadata else '-' }} chars</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% elif searched %}
<div class="empty-state">
    <p>No similar contracts found above {{ min_sim }} similarity threshold</p>
</div>
{% endif %}

<div style="margin-top: 30px; padding: 20px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;">
    <h4 style="margin-bottom: 10px;">Index Status</h4>
    <p style="color: var(--text-secondary);">Total indexed: <strong>{{ index_stats.total_contracts }}</strong> contracts</p>
    <p style="color: var(--text-secondary); margin-top: 10px;">To index more contracts:</p>
    <pre style="background: var(--bg-dark); padding: 12px; border-radius: 6px; margin-top: 10px;">python similarity_cli.py index sources/</pre>
</div>
"""


@app.route("/similarity", methods=["GET", "POST"])
def similarity_search():
    """Similarity search page."""
    code = ""
    address = ""
    chain = "56"
    results = []
    searched = False
    min_sim = 0.7
    top_n = 10
    error = None
    index_stats = {"total_contracts": 0}

    # Try to get index stats
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

        # If address provided, fetch code from Sourcify/local
        if address and address.startswith("0x"):
            chain_id = int(chain)
            # Try local first
            sources_dir = Path("sources") / f"{chain_id}_{address.lower()}"
            if sources_dir.exists():
                sol_files = list(sources_dir.glob("*.sol"))
                if sol_files:
                    code = sol_files[0].read_text(encoding="utf-8", errors="ignore")

            # If not local, try fetching from API
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
                        # Get the main contract file
                        code = list(sources.values())[0]
                except Exception as e:
                    error = f"Could not fetch code for {address}: {str(e)}"

        if code:
            try:
                from similarity import SimilarityIndex

                index = SimilarityIndex()
                results = index.find_similar(code, n_results=top_n, min_similarity=min_sim)
            except Exception as e:
                error = f"Similarity search error: {str(e)}"
        elif not error:
            error = "Please provide either a contract address or paste code"

    content = render_template_string(
        SIMILARITY_CONTENT,
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
    return render_template_string(BASE_TEMPLATE, content=content, page="similarity")


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


if __name__ == "__main__":
    _log.info("Starting Contract Registry Web Interface...")
    _log.info("Open http://localhost:5000 in your browser")
    app.run(debug=True, port=5000)
