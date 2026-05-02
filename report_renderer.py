from __future__ import annotations

import html
import re
from typing import Any

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
    "Info": 4,
}


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_severity(sev: str) -> str:
    s = _as_str(sev).strip()
    if not s:
        return "Unknown"
    if s.lower() == "info":
        return "Informational"
    if s.lower() == "informational":
        return "Informational"
    if s.lower() == "critical":
        return "Critical"
    if s.lower() == "high":
        return "High"
    if s.lower() == "medium":
        return "Medium"
    if s.lower() == "low":
        return "Low"
    return s


def render_markdown(report: dict) -> str:
    scope = report.get("scope") if isinstance(report, dict) else {}
    if not isinstance(scope, dict):
        scope = {}

    chain_id = _as_str(scope.get("chain_id") or "Unknown")
    address = _as_str(scope.get("address") or "Unknown")
    files = [_as_str(x) for x in _as_list(scope.get("files")) if _as_str(x)]

    exec_summary = _as_str(report.get("executive_summary"))
    system_overview = _as_str(report.get("system_overview"))
    privileged_roles = _as_str(report.get("privileged_roles"))
    threat_model = _as_str(report.get("threat_model"))

    findings = report.get("findings") if isinstance(report, dict) else []
    if not isinstance(findings, list):
        findings = []

    additional_recs = [_as_str(x) for x in _as_list(report.get("additional_recommendations")) if _as_str(x)]
    verification = [_as_str(x) for x in _as_list(report.get("verification_checklist")) if _as_str(x)]
    limitations = [_as_str(x) for x in _as_list(report.get("limitations")) if _as_str(x)]

    lines: list[str] = []

    lines += ["## Executive Summary", "", exec_summary or "Unknown", ""]

    lines += ["## Scope", ""]
    lines += [f"- Chain ID: `{chain_id}`", f"- Address: `{address}`"]
    if files:
        lines.append("- Files:")
        for f in files:
            lines.append(f"  - `{f}`")
    else:
        lines.append("- Files: `Unknown`")
    lines.append("")

    lines += ["## System Overview", "", system_overview or "Unknown", ""]
    lines += ["## Privileged Roles & Trust Assumptions", "", privileged_roles or "Unknown", ""]
    lines += ["## Attack Surface / Threat Model", "", threat_model or "Unknown", ""]

    lines += ["## Findings Table", ""]
    if findings:
        lines.append("| ID | Severity | Title | Affected Component | Impact |")
        lines.append("|---:|:---------|:------|:-------------------|:-------|")
        for f in sorted(
            findings, key=lambda x: SEVERITY_ORDER.get(_normalize_severity(_as_str((x or {}).get("severity"))), 99)
        ):
            if not isinstance(f, dict):
                continue
            fid = _as_str(f.get("id") or "")
            sev = _normalize_severity(_as_str(f.get("severity")))
            title = _as_str(f.get("title") or "")
            comp = _as_str(f.get("affected_component") or "")
            impact = _as_str(f.get("impact") or "")
            lines.append(f"| {fid} | {sev} | {title} | {comp} | {impact} |")
    else:
        lines.append("No findings reported.")
    lines.append("")

    lines += ["## Detailed Findings", ""]
    if not findings:
        lines.append("No findings reported.")
        lines.append("")
    else:
        for f in findings:
            if not isinstance(f, dict):
                continue
            fid = _as_str(f.get("id") or "F-??")
            sev = _normalize_severity(_as_str(f.get("severity")))
            title = _as_str(f.get("title") or "Untitled")
            lines.append(f"### {fid}: {title}")
            lines.append("")
            lines.append(f"- Severity: `{sev}`")

            impact = _as_str(f.get("impact"))
            likelihood = _as_str(f.get("likelihood"))
            root_cause = _as_str(f.get("root_cause"))
            rec = _as_str(f.get("recommendation"))
            notes = _as_str(f.get("notes"))
            comp = _as_str(f.get("affected_component"))

            if comp:
                lines.append(f"- Affected: `{comp}`")
            if impact:
                lines.append(f"- Impact: {impact}")
            if likelihood:
                lines.append(f"- Likelihood: {likelihood}")
            if root_cause:
                lines.append(f"- Root cause: {root_cause}")
            if rec:
                lines.append(f"- Recommendation: {rec}")

            locs = f.get("locations")
            if isinstance(locs, list) and locs:
                lines.append("- Locations:")
                for loc in locs[:10]:
                    if not isinstance(loc, dict):
                        continue
                    lf = _as_str(loc.get("file"))
                    ln = loc.get("line")
                    excerpt = _as_str(loc.get("excerpt"))
                    if lf and isinstance(ln, int):
                        lines.append(f"  - `{lf}:{ln}` {('`' + excerpt + '`') if excerpt else ''}".rstrip())
                    elif lf:
                        lines.append(f"  - `{lf}` {('`' + excerpt + '`') if excerpt else ''}".rstrip())

            if notes:
                lines.append(f"- Notes: {notes}")
            lines.append("")

    if additional_recs:
        lines += ["## Additional Recommendations", ""]
        for item in additional_recs:
            lines.append(f"- {item}")
        lines.append("")

    if verification:
        lines += ["## Verification Checklist", ""]
        for item in verification:
            lines.append(f"- {item}")
        lines.append("")

    if limitations:
        lines += ["## Limitations", ""]
        for item in limitations:
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


_SEVERITY_CSS_CLASS = {
    "Critical": "sev-critical",
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
    "Informational": "sev-info",
}

_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_TABLE_SEP_RE = re.compile(r"^\s*\|[\s|:\-]+\|\s*$")
_LIST_ITEM_RE = re.compile(r"^(\s*)- (.*)$")


def _inline_md(text: str) -> str:
    """Escape HTML, then turn ``backtick`` spans into ``<code>`` and tag severity values."""
    escaped = html.escape(text, quote=False)

    def _wrap_code(m: re.Match[str]) -> str:
        inner = m.group(1)
        css = _SEVERITY_CSS_CLASS.get(inner)
        if css:
            return f'<code class="{css}">{inner}</code>'
        return f"<code>{inner}</code>"

    return _INLINE_CODE_RE.sub(_wrap_code, escaped)


def _markdown_to_html(md: str) -> str:
    """Minimal Markdown → HTML converter, scoped to the subset that
    :func:`render_markdown` produces (headings, paragraphs, bullet lists with
    one level of nesting, GFM-style tables, inline backticks, ``---`` rules).

    A general-purpose Markdown library would bring a runtime dependency just
    for this one render path; the dialect we emit is small enough to handle
    inline.
    """
    lines = md.splitlines()
    n = len(lines)
    out: list[str] = []
    list_stack: list[int] = []  # indentation levels of currently open <ul>s

    def close_lists(target_indent: int = -1) -> None:
        while list_stack and list_stack[-1] > target_indent:
            out.append("</ul>")
            list_stack.pop()

    i = 0
    while i < n:
        raw = lines[i]
        stripped = raw.strip()

        if not stripped:
            close_lists()
            i += 1
            continue

        if stripped == "---":
            close_lists()
            out.append("<hr/>")
            i += 1
            continue

        for level, prefix in ((3, "### "), (2, "## "), (1, "# ")):
            if stripped.startswith(prefix):
                close_lists()
                out.append(f"<h{level}>{_inline_md(stripped[len(prefix) :].strip())}</h{level}>")
                i += 1
                break
        else:
            # Table: header row followed by `|---|---|` separator
            if stripped.startswith("|") and i + 1 < n and _TABLE_SEP_RE.match(lines[i + 1]):
                close_lists()
                header = [c.strip() for c in stripped.strip("|").split("|")]
                i += 2  # skip header + separator
                rows: list[list[str]] = []
                while i < n and lines[i].strip().startswith("|"):
                    rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                    i += 1
                out.append("<table>")
                out.append("<thead><tr>" + "".join(f"<th>{_inline_md(c)}</th>" for c in header) + "</tr></thead>")
                out.append("<tbody>")
                for row in rows:
                    out.append("<tr>" + "".join(f"<td>{_inline_md(c)}</td>" for c in row) + "</tr>")
                out.append("</tbody></table>")
                continue

            li_match = _LIST_ITEM_RE.match(raw)
            if li_match:
                indent = len(li_match.group(1))
                text = li_match.group(2)
                # Open new lists for deeper indents, close any that are deeper than us.
                while not list_stack or list_stack[-1] < indent:
                    out.append("<ul>")
                    list_stack.append(indent)
                close_lists(indent)
                out.append(f"<li>{_inline_md(text)}</li>")
                i += 1
                continue

            # Paragraph: collect consecutive non-blank, non-special lines.
            close_lists()
            para: list[str] = []
            while i < n:
                cur = lines[i]
                cs = cur.strip()
                if not cs or cs == "---":
                    break
                if cs.startswith(("# ", "## ", "### ", "- ")):
                    break
                if cs.startswith("|"):
                    break
                para.append(cs)
                i += 1
            if para:
                out.append(f"<p>{_inline_md(' '.join(para))}</p>")

    close_lists()
    return "\n".join(out)


def render_html(report: dict, *, title: str = "Smart Contract Audit Report") -> str:
    """Render the audit report as styled HTML with a severity summary."""
    md_content = render_markdown(report)
    body_html = _markdown_to_html(md_content)

    findings = report.get("findings", []) if isinstance(report, dict) else []
    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        if isinstance(f, dict):
            sev = _normalize_severity(_as_str(f.get("severity")))
            if sev in severity_counts:
                severity_counts[sev] += 1

    mermaid_chart = ""
    if any(severity_counts.values()):
        pie_rows = "\n".join(f'    "{k}" : {v}' for k, v in severity_counts.items() if v > 0)
        mermaid_chart = f'<pre class="mermaid">\npie title Findings by Severity\n{pie_rows}\n</pre>'

    safe_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        h1, h2, h3 {{ color: #fff; border-bottom: 1px solid var(--border-color); padding-bottom: 0.4rem; }}
        h2 {{ margin-top: 2rem; }}
        code {{ background: var(--bg-secondary); padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.9em; }}
        pre {{ background: var(--bg-secondary); padding: 1rem; border-radius: 8px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ border: 1px solid var(--border-color); padding: 0.6rem 0.75rem; text-align: left; vertical-align: top; }}
        th {{ background: var(--bg-secondary); }}
        ul {{ padding-left: 1.4rem; }}
        ul ul {{ margin: 0.2rem 0; }}
        hr {{ border: 0; border-top: 1px solid var(--border-color); margin: 1.5rem 0; }}
        .sev-critical {{ color: var(--critical); font-weight: bold; }}
        .sev-high     {{ color: var(--high); font-weight: bold; }}
        .sev-medium   {{ color: var(--medium); }}
        .sev-low      {{ color: var(--low); }}
        .sev-info     {{ color: var(--info); }}
        .chart-container {{ background: var(--bg-secondary); padding: 1rem; border-radius: 8px; margin: 1rem 0; }}
        .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
        .stat-card {{ background: var(--bg-secondary); padding: 1rem; border-radius: 8px; min-width: 120px; text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.875rem; }}
    </style>
</head>
<body>
    <h1>{safe_title}</h1>

    <div class="stats">
        <div class="stat-card"><div class="stat-value sev-critical">{severity_counts["Critical"]}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value sev-high">{severity_counts["High"]}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value sev-medium">{severity_counts["Medium"]}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value sev-low">{severity_counts["Low"]}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value sev-info">{severity_counts["Informational"]}</div><div class="stat-label">Info</div></div>
    </div>

    <div class="chart-container">
        {mermaid_chart}
    </div>

    <main class="content">
{body_html}
    </main>

    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
</body>
</html>
"""
