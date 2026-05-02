"""Tests for report_renderer (Markdown + HTML rendering)."""

from __future__ import annotations

from report_renderer import _markdown_to_html, render_html, render_markdown


def _sample_report() -> dict:
    return {
        "scope": {"chain_id": 56, "address": "0xdeadbeef", "files": ["Token.sol", "Vault.sol"]},
        "executive_summary": "Two issues with <script>tags</script> were found.",
        "system_overview": "A simple ERC20 + Vault.",
        "privileged_roles": "Owner controls minting.",
        "threat_model": "Reentrancy and access control.",
        "findings": [
            {
                "id": "F-01",
                "severity": "Critical",
                "title": "Unrestricted mint",
                "affected_component": "Token.mint",
                "impact": "Anyone can mint",
                "likelihood": "High",
                "root_cause": "Missing onlyOwner",
                "recommendation": "Add onlyOwner modifier",
                "locations": [{"file": "Token.sol", "line": 42, "excerpt": "function mint()"}],
            },
            {"id": "F-02", "severity": "Medium", "title": "tx.origin used"},
        ],
        "additional_recommendations": ["Add tests", "Run slither"],
        "verification_checklist": ["onlyOwner enforced"],
        "limitations": ["No fork tests"],
    }


# -- render_markdown --------------------------------------------------------


def test_render_markdown_includes_all_sections() -> None:
    md = render_markdown(_sample_report())
    for heading in (
        "## Executive Summary",
        "## Scope",
        "## System Overview",
        "## Privileged Roles & Trust Assumptions",
        "## Attack Surface / Threat Model",
        "## Findings Table",
        "## Detailed Findings",
        "## Additional Recommendations",
        "## Verification Checklist",
        "## Limitations",
    ):
        assert heading in md, f"missing section: {heading}"


def test_render_markdown_findings_sorted_by_severity_in_table() -> None:
    md = render_markdown(_sample_report())
    table = md.split("## Findings Table", 1)[1].split("## Detailed Findings", 1)[0]
    crit_idx = table.index("F-01")
    med_idx = table.index("F-02")
    assert crit_idx < med_idx, "Critical should appear before Medium in the findings table"


def test_render_markdown_handles_empty_report() -> None:
    md = render_markdown({})
    assert "## Executive Summary" in md
    assert "Unknown" in md  # placeholder for missing fields
    assert "No findings reported." in md


def test_render_markdown_unknown_severity_passes_through() -> None:
    md = render_markdown({"findings": [{"id": "F-1", "severity": "Catastrophic", "title": "X"}]})
    # Unknown severities are not normalised to Critical/etc, they appear verbatim.
    assert "Catastrophic" in md


# -- _markdown_to_html (the inline converter) -------------------------------


def test_markdown_to_html_headings_and_paragraphs() -> None:
    out = _markdown_to_html("## Title\n\nFirst paragraph.\n\nSecond paragraph.")
    assert "<h2>Title</h2>" in out
    assert "<p>First paragraph.</p>" in out
    assert "<p>Second paragraph.</p>" in out


def test_markdown_to_html_bullet_list_with_nesting() -> None:
    md = "- top1\n- top2\n  - nested\n- top3"
    out = _markdown_to_html(md)
    assert out.count("<ul>") == 2
    assert out.count("</ul>") == 2
    assert "<li>nested</li>" in out


def test_markdown_to_html_table() -> None:
    md = "| A | B |\n|:---|:---|\n| 1 | 2 |\n| 3 | 4 |"
    out = _markdown_to_html(md)
    assert "<table>" in out and "</table>" in out
    assert "<th>A</th>" in out
    assert "<td>3</td>" in out


def test_markdown_to_html_inline_code_and_severity_class() -> None:
    out = _markdown_to_html("- Severity: `Critical`")
    assert '<code class="sev-critical">Critical</code>' in out


def test_markdown_to_html_escapes_html_in_text() -> None:
    out = _markdown_to_html("paragraph with <script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_markdown_to_html_horizontal_rule() -> None:
    out = _markdown_to_html("Before\n\n---\n\nAfter")
    assert "<hr/>" in out


# -- render_html ------------------------------------------------------------


def test_render_html_full_doc_structure() -> None:
    out = render_html(_sample_report(), title="My <script> Audit")
    # title is escaped
    assert "&lt;script&gt;" in out
    # base layout pieces
    assert "<!DOCTYPE html>" in out
    assert '<meta charset="UTF-8">' in out
    # severity stat cards
    assert ">1<" in out  # Critical count == 1
    # Mermaid chart present when there are findings
    assert "pie title Findings by Severity" in out
    # Severity tagging makes it through to the HTML body
    assert '<code class="sev-critical">Critical</code>' in out
    # Real markdown→html, not <pre> dump of raw markdown
    assert "<pre>## " not in out


def test_render_html_no_findings_skips_pie_chart() -> None:
    out = render_html({"findings": []})
    assert "pie title Findings by Severity" not in out
    # But the page still renders
    assert "<h1>" in out
