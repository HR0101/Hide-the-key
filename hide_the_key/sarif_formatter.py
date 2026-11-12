"""SARIF (Static Analysis Results Interchange Format) exporter for GitHub Code Scanning."""

import json
from typing import List, Dict
from .scanner import ScanSummary, FileIssue
from .constants import SECRET_SIGNATURES


def export_sarif(summary: ScanSummary, output_path: str) -> str:
    """
    Export scan issues in SARIF v2.1.0 format.
    Compatible with GitHub Code Scanning (upload-sarif action) and other security dashboards.
    """
    rules = []
    rule_ids = set()

    for rule in SECRET_SIGNATURES:
        rule_ids.add(rule["id"])
        rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "shortDescription": {"text": f"Detects exposed {rule['name']}"},
            "fullDescription": {"text": f"Checks for hardcoded {rule['name']} in repository files."},
            "defaultConfiguration": {
                "level": "error" if rule["severity"] == "CRITICAL" else "warning"
            },
            "properties": {
                "tags": ["security", "secret", "credentials"],
                "precision": "high",
            },
        })

    # Additional file-level rules
    file_rules = [
        ("SECRET_FILE_TRACKED", "Tracked Secret File", "error"),
        ("SECRET_FILE_NOT_IGNORED", "Secret File Missing from .gitignore", "warning"),
        ("UNWANTED_FILE_TRACKED", "Unwanted System / DB File Tracked", "warning"),
        ("GIT_HISTORY_LEAK", "Committed Secret in Git History", "error"),
        ("STAGED_DIFF_KEY", "Secret Staged in Git Index", "error"),
    ]
    for r_id, r_name, r_level in file_rules:
        if r_id not in rule_ids:
            rule_ids.add(r_id)
            rules.append({
                "id": r_id,
                "name": r_name,
                "shortDescription": {"text": r_name},
                "defaultConfiguration": {"level": r_level},
                "properties": {
                    "tags": ["security", "git", "gitignore"],
                },
            })

    results = []
    root = summary.git_root or summary.target_dir

    for issue in summary.issues:
        if issue.severity == "SAFE":
            continue

        # Calculate relative path
        import os
        rel_uri = os.path.relpath(issue.file_path, root).replace("\\", "/")

        rule_id = issue.details.get("rule_id", issue.issue_type)
        line = issue.details.get("line_number", 1)
        if line <= 0:
            line = 1

        level = "error" if issue.severity == "CRITICAL" else "warning"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{issue.message}. Recommended action: {issue.suggestion or 'Review file'}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HideTheKey",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Rhara/Hide-the-key",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, ensure_ascii=False)

    return output_path
