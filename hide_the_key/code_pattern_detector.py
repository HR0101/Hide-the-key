"""Detect dangerous code patterns, insecure references, and public client exposures."""

import os
import re
from typing import List, Dict, Optional
from .constants import (
    PUBLIC_ENV_PREFIXES,
    SENSITIVE_KEYWORD_REGEX,
    DANGEROUS_CODE_PATTERNS,
    MAX_SCAN_FILE_SIZE,
)
from .secret_detector import is_binary_file, is_safe_filename, mask_secret

DUMMY_PLACEHOLDERS = [
    "example",
    "dummy",
    "placeholder",
    "sample",
    "changeme",
    "your_",
    "mock",
    "xxxx",
    "12345",
    "fake",
    "<your",
    "insert-key",
]


def is_pattern_false_positive(matched_val: str, line: str) -> bool:
    """Filter out harmless dummy values in dangerous code patterns."""
    line_lower = line.lower()
    for term in DUMMY_PLACEHOLDERS:
        if term in line_lower:
            return True
    return False


# Regex to detect public exposure of secrets in frontend code or env files
# Specifically target environment variable accesses like process.env.NEXT_PUBLIC_... or import.meta.env.VITE_...
PUBLIC_ENV_ASSIGNMENT_REGEX = re.compile(
    r"""^\s*(?:export\s+)?(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_|PUBLIC_)([A-Z0-9_]+)\s*[:=]\s*(.+)$"""
)
PUBLIC_ENV_REFERENCE_REGEX = re.compile(
    r"""\b(?:process\.env\.|import\.meta\.env\.|env\.)(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_|PUBLIC_)([A-Z0-9_]+)\b"""
)


def scan_file_for_code_patterns(file_path: str) -> List[Dict[str, any]]:
    """
    Scan a file for dangerous code patterns and insecure secret references.
    Returns list of issue dicts.
    """
    findings = []
    base_name = os.path.basename(file_path)

    if is_safe_filename(base_name):
        return []

    # Skip documentation files for code pattern analysis
    _, ext = os.path.splitext(base_name.lower())
    if ext in (".md", ".markdown", ".rst", ".txt"):
        return []

    try:
        size = os.path.getsize(file_path)
        if size > MAX_SCAN_FILE_SIZE:
            return []
    except OSError:
        return []

    if is_binary_file(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    is_env_file = ".env" in base_name

    for line_idx, line in enumerate(lines, start=1):
        if len(line) > 2000:
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
            # Still check for hardcoded secrets in comments if applicable, but skip code pattern check
            continue

        # 1. Check for Public Client Environment Variable Exposure
        # e.g. NEXT_PUBLIC_OPENAI_API_KEY=... or process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY
        if is_env_file:
            match = PUBLIC_ENV_ASSIGNMENT_REGEX.match(stripped)
            if match:
                prefix = match.group(1)
                var_suffix = match.group(2)
                value = match.group(3).strip().strip("'\"")

                if SENSITIVE_KEYWORD_REGEX.search(var_suffix):
                    findings.append({
                        "file_path": file_path,
                        "line_number": line_idx,
                        "line_content": stripped,
                        "pattern_id": "public_client_secret_exposure",
                        "pattern_name": "Public Client Secret Exposure (Exposed to Browser Bundle!)",
                        "severity": "CRITICAL",
                        "message": f"Environment variable '{prefix}{var_suffix}' exposes a sensitive secret to the browser! Variables with prefix '{prefix}' are bundled into public client-side JavaScript.",
                        "suggestion": f"Rename '{prefix}{var_suffix}' to '{var_suffix}' (without '{prefix}') and only access it on the server/backend.",
                    })
        else:
            # Code file: check process.env.NEXT_PUBLIC_...
            for ref_match in PUBLIC_ENV_REFERENCE_REGEX.finditer(stripped):
                prefix = ref_match.group(1)
                var_suffix = ref_match.group(2)
                if SENSITIVE_KEYWORD_REGEX.search(var_suffix):
                    findings.append({
                        "file_path": file_path,
                        "line_number": line_idx,
                        "line_content": stripped,
                        "pattern_id": "public_client_secret_exposure",
                        "pattern_name": "Public Client Secret Reference (Exposed to Browser)",
                        "severity": "CRITICAL",
                        "message": f"Referencing '{prefix}{var_suffix}' in client code exposes this secret to any visitor via browser DevTools (F12)!",
                        "suggestion": f"Move the API call to a backend API route (e.g. Next.js /api/ or Server Action) and use a non-public environment variable.",
                    })

        # 2. Check for Dangerous Code Patterns (fallbacks, URLs, logging, docker)
        for pattern_def in DANGEROUS_CODE_PATTERNS:
            regex = pattern_def["pattern"]
            matches = regex.finditer(stripped)
            for m in matches:
                matched_val = m.group(1) if m.lastindex else m.group(0)

                # Skip false positives
                if is_pattern_false_positive(matched_val, stripped):
                    continue

                masked = mask_secret(matched_val) if len(matched_val) > 8 else matched_val

                findings.append({
                    "file_path": file_path,
                    "line_number": line_idx,
                    "line_content": stripped,
                    "pattern_id": pattern_def["id"],
                    "pattern_name": pattern_def["name"],
                    "severity": pattern_def["severity"],
                    "message": f"{pattern_def['name']} on line {line_idx}: {pattern_def['description']}",
                    "suggestion": pattern_def["suggestion"],
                })

    return findings
