"""Generate professional, unslopped interactive HTML audit reports.

Built with architectural precision:
- 4px rhythm grid
- Graphite neutral ramp with single-accent semantic indicators
- Unified 16px/1.5-stroke inline SVG icons (Zero emojis)
- Tabular figures and typography with strict 400/500 weight discipline
- Instant filtering (All / Issues / Clean) and one-click copy buttons
- Pure single-file standalone HTML (Zero external CDN/CSS dependencies)
"""

import os
import html
import time
from typing import List, Dict
from .global_scanner import GlobalScanResult
from .scanner import ScanSummary, FileIssue


# Clean SVG Icons (16px, 1.5 stroke, no external network)
ICONS = {
    "shield": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>""",
    "alert_circle": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>""",
    "alert_triangle": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>""",
    "check_circle": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>""",
    "folder": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>""",
    "file_text": """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>""",
    "terminal": """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>""",
    "copy": """<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>""",
    "check": """<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>""",
    "chevron": """<svg class="chevron-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>""",
    "search": """<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>""",
}


def render_issue_block(issue: FileIssue, root_path: str) -> str:
    """Render a single security issue card with clean monospace details."""
    severity = issue.severity.lower()
    rel_path = os.path.relpath(issue.file_path, root_path)
    line_num = issue.details.get("line_number")
    line_suffix = f":{line_num}" if line_num and line_num > 0 else ""

    badge_label = "Critical" if issue.severity == "CRITICAL" else ("High" if issue.severity == "HIGH" else "Notice")
    badge_class = f"badge-{severity}"

    fix_snippet = ""
    if issue.suggestion:
        escaped_fix = html.escape(issue.suggestion)
        fix_snippet = f"""
        <div class="fix-container">
            <span class="fix-label">{ICONS['terminal']} Recommended fix</span>
            <div class="code-box">
                <code>{escaped_fix}</code>
                <button class="copy-btn" onclick="copyCode(this, '{escaped_fix}')" title="Copy to clipboard">
                    <span class="copy-idle">{ICONS['copy']} Copy</span>
                    <span class="copy-done" style="display:none;">{ICONS['check']} Copied</span>
                </button>
            </div>
        </div>
        """

    return f"""
    <div class="issue-card issue-{severity}">
        <div class="issue-top">
            <div class="issue-path-wrap">
                <span class="file-icon">{ICONS['file_text']}</span>
                <span class="file-path">{html.escape(rel_path)}{line_suffix}</span>
            </div>
            <span class="badge {badge_class}">{badge_label}</span>
        </div>
        <div class="issue-message">{html.escape(issue.message)}</div>
        {fix_snippet}
    </div>
    """


def render_repository_accordion(summary: ScanSummary) -> str:
    """Render clean, collapsible directory card."""
    is_critical = summary.critical_count > 0
    is_high = summary.high_count > 0
    is_clean = (summary.critical_count == 0 and summary.high_count == 0 and summary.medium_count == 0)

    category_class = "cat-critical" if is_critical else ("cat-high" if is_high else "cat-clean")
    is_open = "open" if (is_critical or is_high) else ""

    status_badge = ""
    if is_critical:
        status_badge = f'<span class="badge badge-critical">{summary.critical_count} critical</span>'
    elif is_high:
        status_badge = f'<span class="badge badge-high">{summary.high_count} high</span>'
    elif is_clean:
        status_badge = f'<span class="badge badge-safe">Protected</span>'
    else:
        status_badge = f'<span class="badge badge-notice">{summary.medium_count} notice</span>'

    # Filter out safe issues from expanded view to keep clean
    actionable_issues = [i for i in summary.issues if i.severity != "SAFE"]

    issues_html = ""
    if actionable_issues:
        issues_html = "\n".join(render_issue_block(issue, summary.target_dir) for issue in actionable_issues)
    else:
        issues_html = f"""
        <div class="clean-state">
            <span class="clean-icon">{ICONS['check_circle']}</span>
            <span>No secrets or unignored files found. All files are safely excluded or free of credentials.</span>
        </div>
        """

    dir_basename = os.path.basename(summary.target_dir) or summary.target_dir

    return f"""
    <details class="repo-row {category_class}" {is_open} data-name="{html.escape(summary.target_dir.lower())}">
        <summary class="repo-summary">
            <div class="repo-left">
                <span class="dir-icon">{ICONS['folder']}</span>
                <div class="dir-texts">
                    <span class="dir-name">{html.escape(dir_basename)}</span>
                    <span class="dir-subpath">{html.escape(summary.target_dir)}</span>
                </div>
            </div>
            <div class="repo-right">
                <span class="file-stat">{summary.scanned_files_count} files</span>
                {status_badge}
                {ICONS['chevron']}
            </div>
        </summary>
        <div class="repo-content">
            {issues_html}
        </div>
    </details>
    """


def generate_html_report(result: GlobalScanResult, output_path: str) -> str:
    """Generate high-craft, unslopped HTML report for global or single scan."""
    output_path = os.path.abspath(output_path)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    # Sort repositories: Critical first, then High, then clean
    sorted_summaries = sorted(
        result.summaries,
        key=lambda s: (s.critical_count * 1000 + s.high_count * 100 + s.medium_count),
        reverse=True,
    )

    rows_html = "\n".join(render_repository_accordion(s) for s in sorted_summaries)

    total_issues = result.total_critical + result.total_high
    header_status = f"{total_issues} exposures requiring attention" if total_issues > 0 else "All inspected directories protected"

    html_code = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HideTheKey Security Audit Report</title>
    <style>
        :root {{
            /* Graphite Neutral Ramp */
            --bg-base: #0a0d12;
            --surface-1: #11161d;
            --surface-2: #161c26;
            --surface-3: #1d2532;
            --border-hairline: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(255, 255, 255, 0.16);
            
            --text-primary: #f0f3f6;
            --text-secondary: #8b949e;
            --text-muted: #57606a;

            /* Muted Precision Accents */
            --red-tint: rgba(235, 87, 87, 0.12);
            --red-border: rgba(235, 87, 87, 0.35);
            --red-text: #ff7b72;

            --amber-tint: rgba(217, 130, 43, 0.12);
            --amber-border: rgba(217, 130, 43, 0.35);
            --amber-text: #e3b341;

            --green-tint: rgba(46, 160, 67, 0.12);
            --green-border: rgba(46, 160, 67, 0.35);
            --green-text: #3fb950;

            --blue-tint: rgba(56, 139, 253, 0.12);
            --blue-border: rgba(56, 139, 253, 0.35);
            --blue-text: #58a6ff;

            --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
            --font-mono: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            padding: 32px 20px;
        }}

        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}

        /* App Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-hairline);
            margin-bottom: 24px;
        }}

        .brand-row {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 4px;
        }}

        .brand-icon {{
            color: var(--blue-text);
            display: flex;
        }}

        h1 {{
            font-size: 18px;
            font-weight: 500;
            letter-spacing: -0.01em;
            color: var(--text-primary);
        }}

        .subtitle {{
            font-size: 12px;
            color: var(--text-secondary);
        }}

        .header-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
            font-variant-numeric: tabular-nums;
        }}

        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}

        .metric-card {{
            background: var(--surface-1);
            border: 1px solid var(--border-hairline);
            border-radius: 8px;
            padding: 14px 16px;
        }}

        .metric-val {{
            font-size: 26px;
            font-weight: 500;
            line-height: 1.1;
            margin-bottom: 4px;
            font-variant-numeric: tabular-nums;
            font-family: var(--font-mono);
        }}

        .metric-val.val-red {{ color: var(--red-text); }}
        .metric-val.val-amber {{ color: var(--amber-text); }}
        .metric-val.val-green {{ color: var(--green-text); }}
        .metric-val.val-neutral {{ color: var(--text-primary); }}

        .metric-label {{
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        /* Controls: Filter Tabs + Search */
        .controls-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin-bottom: 16px;
        }}

        .tabs-wrap {{
            display: flex;
            background: var(--surface-1);
            border: 1px solid var(--border-hairline);
            border-radius: 6px;
            padding: 2px;
            gap: 2px;
        }}

        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-family: var(--font-sans);
            font-size: 12px;
            font-weight: 400;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s ease;
            font-variant-numeric: tabular-nums;
        }}

        .tab-btn:hover {{
            color: var(--text-primary);
        }}

        .tab-btn.active {{
            background: var(--surface-3);
            color: var(--text-primary);
            font-weight: 500;
        }}

        .search-box {{
            display: flex;
            align-items: center;
            background: var(--surface-1);
            border: 1px solid var(--border-hairline);
            border-radius: 6px;
            padding: 0 10px;
            width: 260px;
            gap: 8px;
            color: var(--text-muted);
        }}

        .search-box:focus-within {{
            border-color: var(--border-hover);
            color: var(--text-secondary);
        }}

        .search-box input {{
            background: transparent;
            border: none;
            outline: none;
            color: var(--text-primary);
            font-size: 12px;
            font-family: var(--font-sans);
            padding: 6px 0;
            width: 100%;
        }}

        .search-box input::placeholder {{
            color: var(--text-muted);
        }}

        /* Repository Accordion Rows */
        .repo-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .repo-row {{
            background: var(--surface-1);
            border: 1px solid var(--border-hairline);
            border-radius: 8px;
            overflow: hidden;
            transition: border-color 0.15s ease;
        }}

        .repo-row:hover {{
            border-color: var(--border-hover);
        }}

        .repo-summary {{
            list-style: none;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            background: var(--surface-1);
        }}

        .repo-summary::-webkit-details-marker {{ display: none; }}

        .repo-left {{
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
        }}

        .dir-icon {{
            color: var(--text-muted);
            display: flex;
            flex-shrink: 0;
        }}

        .dir-texts {{
            display: flex;
            align-items: baseline;
            gap: 8px;
            min-width: 0;
        }}

        .dir-name {{
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
        }}

        .dir-subpath {{
            font-size: 11px;
            color: var(--text-muted);
            font-family: var(--font-mono);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .repo-right {{
            display: flex;
            align-items: center;
            gap: 12px;
            flex-shrink: 0;
        }}

        .file-stat {{
            font-size: 11px;
            color: var(--text-muted);
            font-variant-numeric: tabular-nums;
        }}

        .chevron-icon {{
            color: var(--text-muted);
            transition: transform 0.2s ease;
        }}

        details[open] .chevron-icon {{
            transform: rotate(180deg);
        }}

        /* Badges */
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            line-height: 1.4;
            font-variant-numeric: tabular-nums;
        }}

        .badge-critical {{
            background: var(--red-tint);
            color: var(--red-text);
            border: 1px solid var(--red-border);
        }}

        .badge-high {{
            background: var(--amber-tint);
            color: var(--amber-text);
            border: 1px solid var(--amber-border);
        }}

        .badge-safe {{
            background: var(--green-tint);
            color: var(--green-text);
            border: 1px solid var(--green-border);
        }}

        .badge-notice {{
            background: var(--blue-tint);
            color: var(--blue-text);
            border: 1px solid var(--blue-border);
        }}

        /* Expanded Details Content */
        .repo-content {{
            padding: 12px 16px 16px;
            border-top: 1px solid var(--border-hairline);
            background: #0e1218;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .issue-card {{
            background: var(--surface-1);
            border: 1px solid var(--border-hairline);
            border-radius: 6px;
            padding: 12px 14px;
        }}

        .issue-card.issue-critical {{ border-left: 3px solid var(--red-text); }}
        .issue-card.issue-high {{ border-left: 3px solid var(--amber-text); }}

        .issue-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }}

        .issue-path-wrap {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-primary);
        }}

        .file-icon {{
            color: var(--text-muted);
            display: flex;
        }}

        .issue-message {{
            color: var(--text-secondary);
            font-size: 12px;
            margin-bottom: 8px;
        }}

        .fix-container {{
            background: var(--surface-2);
            border: 1px solid var(--border-hairline);
            border-radius: 4px;
            padding: 8px 10px;
        }}

        .fix-label {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}

        .code-box {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
        }}

        .code-box code {{
            font-family: var(--font-mono);
            font-size: 12px;
            color: #79c0ff;
            word-break: break-all;
        }}

        .copy-btn {{
            background: var(--surface-3);
            border: 1px solid var(--border-hairline);
            color: var(--text-secondary);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: var(--font-sans);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            flex-shrink: 0;
            transition: all 0.15s ease;
        }}

        .copy-btn:hover {{
            color: var(--text-primary);
            border-color: var(--border-hover);
        }}

        .clean-state {{
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 12px;
            padding: 8px 0;
        }}

        .clean-icon {{
            color: var(--green-text);
            display: flex;
        }}

        footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid var(--border-hairline);
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand-row">
                    <span class="brand-icon">{ICONS['shield']}</span>
                    <h1>HideTheKey Security Audit</h1>
                </div>
                <div class="subtitle">{header_status} • Root: {html.escape(result.start_root)}</div>
            </div>
            <div class="header-meta">
                <div>Scan completed {now_str}</div>
                <div>Duration: {result.duration_seconds:.2f}s</div>
            </div>
        </header>

        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-val val-red">{result.total_critical}</div>
                <div class="metric-label">Critical (Tracked / Exposed)</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-amber">{result.total_high}</div>
                <div class="metric-label">High Risk (.gitignore Missing)</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-neutral">{len(result.discovered_dirs)}</div>
                <div class="metric-label">Directories Audited</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-green">{result.total_scanned_files}</div>
                <div class="metric-label">Files Inspected</div>
            </div>
        </section>

        <section class="controls-bar">
            <div class="tabs-wrap">
                <button class="tab-btn active" onclick="setFilter('all', this)">All ({len(result.summaries)})</button>
                <button class="tab-btn" onclick="setFilter('issues', this)">Issues Only ({sum(1 for s in result.summaries if s.critical_count > 0 or s.high_count > 0)})</button>
                <button class="tab-btn" onclick="setFilter('clean', this)">Clean ({sum(1 for s in result.summaries if s.critical_count == 0 and s.high_count == 0 and s.medium_count == 0)})</button>
            </div>
            <div class="search-box">
                {ICONS['search']}
                <input type="text" id="searchInput" placeholder="Filter directories..." oninput="handleSearch()">
            </div>
        </section>

        <section class="repo-list" id="repoList">
            {rows_html}
        </section>

        <footer>
            <span>HideTheKey Security Gate</span>
            <span>Zero-dependency local auditor</span>
        </footer>
    </div>

    <script>
        let currentFilter = 'all';

        function setFilter(type, btn) {{
            currentFilter = type;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilterAndSearch();
        }}

        function handleSearch() {{
            applyFilterAndSearch();
        }}

        function applyFilterAndSearch() {{
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const rows = document.querySelectorAll('.repo-row');

            rows.forEach(row => {{
                const name = row.getAttribute('data-name') || '';
                const matchesQuery = !query || name.includes(query);

                let matchesFilter = true;
                if (currentFilter === 'issues') {{
                    matchesFilter = row.classList.contains('cat-critical') || row.classList.contains('cat-high');
                }} else if (currentFilter === 'clean') {{
                    matchesFilter = row.classList.contains('cat-clean');
                }}

                if (matchesQuery && matchesFilter) {{
                    row.style.display = 'block';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function copyCode(btn, text) {{
            navigator.clipboard.writeText(text).then(() => {{
                const idle = btn.querySelector('.copy-idle');
                const done = btn.querySelector('.copy-done');
                idle.style.display = 'none';
                done.style.display = 'inline-flex';
                setTimeout(() => {{
                    idle.style.display = 'inline-flex';
                    done.style.display = 'none';
                }}, 1800);
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_code)

    return output_path


def generate_html_report_for_single(summary: ScanSummary, output_path: str) -> str:
    """Generate HTML report for a single repository or directory scan."""
    wrapper = GlobalScanResult(summary.target_dir)
    wrapper.discovered_dirs = [summary.target_dir]
    wrapper.summaries = [summary]
    wrapper.total_scanned_files = summary.scanned_files_count
    return generate_html_report(wrapper, output_path)
