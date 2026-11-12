"""CI/CD integration for GitHub Actions and Git hooks."""

import os
from typing import List, Optional
from .scanner import ScanSummary, FileIssue


def is_github_actions() -> bool:
    """Check if currently running inside GitHub Actions CI."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def emit_github_actions_annotations(summary: ScanSummary, repo_root: Optional[str] = None):
    """
    Emit GitHub Actions workflow commands for in-line PR annotations.
    Format: ::error file={file},line={line},title={title}::{message}
    """
    root = repo_root or summary.git_root or summary.target_dir

    for issue in summary.issues:
        if issue.severity not in ("CRITICAL", "HIGH"):
            continue

        rel_path = os.path.relpath(issue.file_path, root)
        line = issue.details.get("line_number", 1)
        if line <= 0:
            line = 1

        title = f"Secret Leak Detected ({issue.issue_type})"
        command = "error" if issue.severity == "CRITICAL" else "warning"
        msg = f"{issue.message} | Fix: {issue.suggestion or 'Remove or ignore this file'}"

        print(f"::{command} file={rel_path},line={line},title={title}::{msg}")


def write_github_step_summary(summary: ScanSummary):
    """Write rich markdown summary to $GITHUB_STEP_SUMMARY for GitHub Actions."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    critical_issues = [i for i in summary.issues if i.severity == "CRITICAL"]
    high_issues = [i for i in summary.issues if i.severity == "HIGH"]

    md_lines = [
        "## 🔍 HideTheKey Security Audit Report",
        "",
        f"- **Target Directory**: `{summary.target_dir}`",
        f"- **Files Inspected**: {summary.scanned_files_count}",
        f"- **Critical Secrets (Tracked/Staged)**: 🚨 **{len(critical_issues)}**",
        f"- **High Risk (.gitignore Missing)**: ⚠️ **{len(high_issues)}**",
        "",
    ]

    if critical_issues or high_issues:
        md_lines.append("### 🚨 Detected Security Issues")
        md_lines.append("| Severity | File | Issue | Recommended Action |")
        md_lines.append("| :--- | :--- | :--- | :--- |")

        for issue in critical_issues + high_issues:
            rel = os.path.relpath(issue.file_path, summary.git_root or summary.target_dir)
            line = issue.details.get("line_number")
            line_str = f":{line}" if line and line > 0 else ""
            badge = "🚨 CRITICAL" if issue.severity == "CRITICAL" else "⚠️ HIGH"
            fix = f"`{issue.suggestion}`" if issue.suggestion else "Review immediately"
            md_lines.append(f"| {badge} | `{rel}{line_str}` | {issue.message} | {fix} |")

        md_lines.append("")
        md_lines.append("> [!CAUTION]")
        md_lines.append("> Commit/Push blocked: Resolve the issues above before pushing to GitHub to prevent credential compromise.")
    else:
        md_lines.append("### ✅ No Leaked Secrets Found")
        md_lines.append("All secret files are safely protected by `.gitignore` and no hardcoded keys were detected.")

    try:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n\n")
    except Exception as e:
        print(f"Warning: Failed to write to GITHUB_STEP_SUMMARY: {e}")


def install_git_hook(repo_root: str, hook_name: str = "pre-commit") -> bool:
    """Install HideTheKey as a local git hook (pre-commit or pre-push)."""
    hooks_dir = os.path.join(repo_root, ".git", "hooks")
    if not os.path.isdir(hooks_dir):
        print(f"Error: Git hooks directory not found at {hooks_dir}")
        return False

    hook_path = os.path.join(hooks_dir, hook_name)

    script_content = f"""#!/usr/bin/env bash
# HideTheKey {hook_name} hook - Prevent secret leaks to GitHub
echo "🔍 Running HideTheKey security audit before {hook_name.replace('pre-', '')}..."

if command -v hide-the-key >/dev/null 2>&1; then
    CMD="hide-the-key ."
else
    # Fallback to python execution if installed in repo
    CMD="python3 -m hide_the_key.cli ."
fi

if ! $CMD; then
    echo ""
    echo "❌ {hook_name.upper()} BLOCKED: Sensitive secrets or unignored secret files detected!"
    echo "💡 Run 'hide-the-key --fix' to auto-fix .gitignore, or resolve the issues above."
    exit 1
fi
"""
    try:
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        os.chmod(hook_path, 0o755)
        return True
    except Exception as e:
        print(f"Error installing hook: {e}")
        return False


def init_github_workflow(repo_root: str) -> str:
    """
    Generate comprehensive .github/workflows/hide-the-key.yml
    Supports:
      - Push on all branches (direct pushes)
      - Pull Requests
      - Nightly scheduled cron audits (with commit history inspection)
      - Manual trigger (workflow_dispatch)
      - SARIF export to GitHub Security Code Scanning tab
    """
    wf_dir = os.path.join(repo_root, ".github", "workflows")
    os.makedirs(wf_dir, exist_ok=True)
    wf_path = os.path.join(wf_dir, "hide-the-key.yml")

    workflow_content = """name: HideTheKey Security & Secret Audit

on:
  push:
    branches: [ "**" ]
    tags: [ "**" ]
  pull_request:
    branches: [ "**" ]
  schedule:
    # Nightly audit at 03:00 UTC (inspects full repository + history)
    - cron: '0 3 * * *'
  workflow_dispatch:
    inputs:
      check_history:
        description: 'Audit git commit history for past leaks'
        required: false
        type: boolean
        default: true

permissions:
  contents: read
  security-events: write

jobs:
  audit-secrets:
    name: Security & .gitignore Audit
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Run HideTheKey Security Audit
        run: |
          HISTORY_FLAG=""
          if [ "${{ github.event_name }}" = "schedule" ] || [ "${{ github.event.inputs.check_history }}" = "true" ]; then
            HISTORY_FLAG="--history"
          fi

          if [ -f "bin/hide-the-key" ]; then
            ./bin/hide-the-key --ci --sarif results.sarif $HISTORY_FLAG
          else
            python3 -m pip install -q git+https://github.com/HR0101/Hide-the-key.git || true
            python3 -m hide_the_key.cli --ci --sarif results.sarif $HISTORY_FLAG
          fi

      - name: Upload SARIF to GitHub Code Scanning Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('results.sarif') != ''
        with:
          sarif_file: results.sarif
          category: hide-the-key
"""
    with open(wf_path, "w", encoding="utf-8") as f:
        f.write(workflow_content)

    return wf_path


def init_gitlab_ci(repo_root: str) -> str:
    """Generate .gitlab-ci.yml template for GitLab CI/CD pipelines."""
    gl_path = os.path.join(repo_root, ".gitlab-ci.yml")
    content = """# HideTheKey GitLab CI/CD Pipeline
stages:
  - test
  - security

secret_audit:
  stage: security
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git
  script:
    - python3 -m pip install -q git+https://github.com/HR0101/Hide-the-key.git || true
    - python3 -m hide_the_key.cli --ci --json > hide-the-key-report.json
  artifacts:
    when: always
    reports:
      secret_detection: hide-the-key-report.json
    paths:
      - hide-the-key-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"""
    with open(gl_path, "w", encoding="utf-8") as f:
        f.write(content)
    return gl_path

