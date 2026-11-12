"""Generate interactive, standalone HTML audit reports."""

import os
import html
from typing import List
from .global_scanner import GlobalScanResult
from .scanner import ScanSummary


def generate_html_report(result: GlobalScanResult, output_path: str) -> str:
    """Generate a modern, responsive HTML report for global scan results."""
    output_path = os.path.abspath(output_path)

    # Filter directories with issues
    dirs_with_critical = [s for s in result.summaries if s.critical_count > 0]
    dirs_with_high = [s for s in result.summaries if s.high_count > 0 and s.critical_count == 0]
    dirs_with_warnings = [s for s in result.summaries if (s.medium_count > 0) and s.critical_count == 0 and s.high_count == 0]
    dirs_safe = [s for s in result.summaries if s.critical_count == 0 and s.high_count == 0 and s.medium_count == 0]

    # Generate repository cards HTML
    cards_html = []
    
    # Render all summaries, sorting critical and high to top
    sorted_summaries = sorted(
        result.summaries,
        key=lambda s: (s.critical_count * 100 + s.high_count * 10 + s.medium_count),
        reverse=True,
    )

    for s in sorted_summaries:
        status_badge = ""
        border_color = "#30363d"
        card_bg = "#161b22"

        if s.critical_count > 0:
            status_badge = f'<span class="badge badge-critical">🚨 CRITICAL ({s.critical_count})</span>'
            border_color = "#f85149"
        elif s.high_count > 0:
            status_badge = f'<span class="badge badge-high">⚠️ HIGH ({s.high_count})</span>'
            border_color = "#d29922"
        elif s.medium_count > 0:
            status_badge = f'<span class="badge badge-medium">⚡ WARNING ({s.medium_count})</span>'
            border_color = "#db6d28"
        else:
            status_badge = f'<span class="badge badge-safe">✅ SAFE ({s.safe_count})</span>'
            border_color = "#238636"

        issues_html = []
        for issue in s.issues:
            severity_class = f"issue-{issue.severity.lower()}"
            escaped_msg = html.escape(issue.message)
            escaped_file = html.escape(issue.file_path)
            fix_html = ""
            if issue.suggestion:
                escaped_fix = html.escape(issue.suggestion)
                fix_html = f'<div class="suggestion">💡 <strong>Fix:</strong> <code>{escaped_fix}</code></div>'

            issues_html.append(f"""
            <div class="issue-item {severity_class}">
                <div class="issue-header">
                    <span class="badge badge-{issue.severity.lower()}">{issue.severity}</span>
                    <span class="file-path">{escaped_file}</span>
                </div>
                <div class="issue-body">{escaped_msg}</div>
                {fix_html}
            </div>
            """)

        is_open = "open" if (s.critical_count > 0 or s.high_count > 0) else ""

        cards_html.append(f"""
        <details class="repo-card" {is_open} style="border-left: 4px solid {border_color};">
            <summary class="repo-summary">
                <div class="repo-info">
                    <span class="repo-name">📂 {html.escape(os.path.basename(s.target_dir))}</span>
                    <span class="repo-path">{html.escape(s.target_dir)}</span>
                </div>
                <div class="repo-badges">
                    {status_badge}
                    <span class="file-count">{s.scanned_files_count} files</span>
                </div>
            </summary>
            <div class="repo-details">
                {''.join(issues_html) if issues_html else '<p class="clean-note">🎉 No secrets or unignored files found in this directory.</p>'}
            </div>
        </details>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HideTheKey - Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-dim: #8b949e;
            --critical: #f85149;
            --high: #d29922;
            --medium: #db6d28;
            --safe: #238636;
            --cyan: #58a6ff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }}
        h1 {{ font-size: 28px; margin-bottom: 8px; color: #fff; }}
        .subtitle {{ color: var(--text-dim); font-size: 14px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .stat-num {{ font-size: 32px; font-weight: bold; margin-bottom: 4px; }}
        .stat-label {{ color: var(--text-dim); font-size: 13px; text-transform: uppercase; }}
        .text-critical {{ color: var(--critical); }}
        .text-high {{ color: var(--high); }}
        .text-safe {{ color: var(--safe); }}
        .text-cyan {{ color: var(--cyan); }}
        .repo-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 14px;
            overflow: hidden;
            transition: all 0.2s ease;
        }}
        .repo-summary {{
            padding: 14px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            list-style: none;
            background-color: #161b22;
        }}
        .repo-summary::-webkit-details-marker {{ display: none; }}
        .repo-info {{ display: flex; flex-direction: column; gap: 4px; text-align: left; }}
        .repo-name {{ font-weight: 600; font-size: 16px; color: #fff; }}
        .repo-path {{ font-size: 12px; color: var(--text-dim); font-family: monospace; }}
        .repo-badges {{ display: flex; align-items: center; gap: 10px; }}
        .badge {{
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(210, 153, 34, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(219, 109, 40, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-safe {{ background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid var(--safe); }}
        .badge-low {{ background: rgba(88, 166, 255, 0.15); color: var(--cyan); border: 1px solid var(--cyan); }}
        .file-count {{ font-size: 12px; color: var(--text-dim); }}
        .repo-details {{
            padding: 16px 20px;
            border-top: 1px solid var(--border-color);
            background: #0d1117;
        }}
        .issue-item {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px 16px;
            margin-bottom: 12px;
        }}
        .issue-critical {{ border-left: 3px solid var(--critical); }}
        .issue-high {{ border-left: 3px solid var(--high); }}
        .issue-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 6px;
        }}
        .file-path {{ font-family: monospace; font-size: 13px; color: #fff; }}
        .issue-body {{ font-size: 13px; color: var(--text-main); margin-bottom: 6px; }}
        .suggestion {{
            background: rgba(88, 166, 255, 0.08);
            border: 1px dashed rgba(88, 166, 255, 0.3);
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 12px;
            color: #79c0ff;
        }}
        code {{
            font-family: monospace;
            background: rgba(110, 118, 129, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            color: #ff7b72;
        }}
        .clean-note {{ color: #3fb950; font-size: 14px; padding: 8px 0; }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-dim);
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 HideTheKey - Security Audit Report</h1>
            <p class="subtitle">Scanned Target: <strong>{html.escape(result.start_root)}</strong> | Completed in {result.duration_seconds:.2f}s</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num text-critical">{result.total_critical}</div>
                <div class="stat-label">🚨 Critical (Tracked/Exposed)</div>
            </div>
            <div class="stat-card">
                <div class="stat-num text-high">{result.total_high}</div>
                <div class="stat-label">⚠️ High (Unprotected .env)</div>
            </div>
            <div class="stat-card">
                <div class="stat-num text-cyan">{len(result.discovered_dirs)}</div>
                <div class="stat-label">📂 Directories Audited</div>
            </div>
            <div class="stat-card">
                <div class="stat-num text-safe">{result.total_scanned_files}</div>
                <div class="stat-label">📄 Files Analyzed</div>
            </div>
        </div>

        <section class="repo-list">
            {''.join(cards_html)}
        </section>

        <footer>
            Generated by <strong>HideTheKey</strong> — Secret Leak Prevention & .gitignore Auditor
        </footer>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
