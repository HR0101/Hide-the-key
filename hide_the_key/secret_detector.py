"""Detect secrets, API keys, and sensitive tokens in text files."""

import os
import math
from typing import List, Dict, Optional
from .constants import (
    SECRET_SIGNATURES,
    FALSE_POSITIVE_SUBSTRINGS,
    SAFE_FILE_SUFFIXES,
    MAX_SCAN_FILE_SIZE,
)


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(secret: str) -> str:
    """Mask a secret string for safe display."""
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix_len = min(6, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_middle = "..." + "*" * 4 + "..."
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


def is_safe_filename(filename: str) -> bool:
    """Check if filename indicates a harmless example or template."""
    lower = filename.lower()
    for suffix in SAFE_FILE_SUFFIXES:
        if lower.endswith(suffix):
            return True
    return False


def is_false_positive(matched_str: str, line: str, rule_id: str) -> bool:
    """
    Determine if a match is a false positive (e.g. placeholder, test string).
    """
    line_lower = line.lower()
    match_lower = matched_str.lower()

    # Check for known placeholder phrases in the line or match
    for term in FALSE_POSITIVE_SUBSTRINGS:
        if term in line_lower:
            return True

    # Check for repetitive single character (e.g. AAAAAAAAA)
    if len(set(matched_str)) <= 3 and len(matched_str) > 10:
        return True

    # Generic assignments require a reasonable entropy
    if rule_id == "generic_secret_assignment":
        entropy = calculate_entropy(matched_str)
        # Random keys typically have Shannon entropy > 3.0
        if entropy < 2.8:
            return True

    return False


def is_binary_file(file_path: str) -> bool:
    """Check if a file appears to be binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def scan_file_for_secrets(file_path: str) -> List[Dict[str, any]]:
    """
    Scan a file line-by-line for embedded API keys and secrets.
    Returns a list of finding dicts.
    """
    findings = []
    base_name = os.path.basename(file_path)

    # Skip files that are clearly templates/examples
    if is_safe_filename(base_name):
        return []

    # Check file size
    try:
        size = os.path.getsize(file_path)
        if size > MAX_SCAN_FILE_SIZE:
            return []
    except OSError:
        return []

    # Skip binary files
    if is_binary_file(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    for line_idx, line in enumerate(lines, start=1):
        # Limit per-line length check to prevent regex DoS on minified files
        if len(line) > 2000:
            continue

        for rule in SECRET_SIGNATURES:
            pattern = rule["pattern"]
            matches = pattern.finditer(line)
            for match in matches:
                # Group 1 if captured, otherwise full match
                matched_val = match.group(1) if match.lastindex else match.group(0)

                if is_false_positive(matched_val, line, rule["id"]):
                    continue

                findings.append(
                    {
                        "file_path": file_path,
                        "line_number": line_idx,
                        "line_content": line.strip(),
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "masked_secret": mask_secret(matched_val),
                    }
                )

    return findings


def scan_diff_for_secrets(diff_text: str) -> List[Dict[str, any]]:
    """Scan git diff text (e.g. staged changes) for secrets in added lines."""
    findings = []
    current_file = ""

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        # Only check added lines
        if not line.startswith("+") or line.startswith("+++"):
            continue

        added_line = line[1:].strip()
        if not added_line or len(added_line) > 2000:
            continue

        base_name = os.path.basename(current_file)
        if is_safe_filename(base_name):
            continue

        for rule in SECRET_SIGNATURES:
            pattern = rule["pattern"]
            matches = pattern.finditer(added_line)
            for match in matches:
                matched_val = match.group(1) if match.lastindex else match.group(0)
                if is_false_positive(matched_val, added_line, rule["id"]):
                    continue

                findings.append(
                    {
                        "file_path": current_file,
                        "line_number": -1,  # In diff
                        "line_content": added_line,
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "masked_secret": mask_secret(matched_val),
                        "is_staged_diff": True,
                    }
                )

    return findings
