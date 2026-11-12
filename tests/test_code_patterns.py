"""Tests for dangerous code patterns and insecure references."""

import os
import tempfile
import unittest
from hide_the_key.code_pattern_detector import scan_file_for_code_patterns


class TestCodePatternDetector(unittest.TestCase):
    def test_next_public_secret_exposure(self):
        # In .env file
        var_name = "".join(["NEXT_", "PUBLIC_", "OPENAI_", "API_KEY"])
        with tempfile.NamedTemporaryFile("w+", suffix=".env", delete=False) as f:
            f.write(f"{var_name}=sk-proj-xyz123\n")
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["pattern_id"], "public_client_secret_exposure")
            self.assertIn("NEXT_PUBLIC_", findings[0]["message"])
        finally:
            os.remove(temp_path)

    def test_next_public_in_js_code(self):
        # In frontend JS file
        var_name = "".join(["NEXT_", "PUBLIC_", "OPENAI_", "API_KEY"])
        with tempfile.NamedTemporaryFile("w+", suffix=".tsx", delete=False) as f:
            f.write(f"const client = new OpenAI({{ apiKey: process.env.{var_name} }});\n")
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["pattern_id"], "public_client_secret_exposure")
        finally:
            os.remove(temp_path)

    def test_env_fallback_leak(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".js", delete=False) as f:
            # Dynamically compose to avoid self-scan match
            fake_key = "".join(["sk-", "proj-", "9876543210zyxwvutsrqponmlkjihgfedcba"])
            f.write(f'const apiKey = process.env.OPENAI_KEY || "{fake_key}";\n')
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            pattern_ids = [item["pattern_id"] for item in findings]
            self.assertIn("env_fallback_leak", pattern_ids)
        finally:
            os.remove(temp_path)

    def test_url_query_secret(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".py", delete=False) as f:
            dummy_key = "".join(["AIzaSy", "BvG52q7W9tKl8OpNmX1_yZvQt94sAbCdE"])
            f.write(f'url = "https://maps.googleapis.com/maps/api/geocode/json?key={dummy_key}&address=Tokyo"\n')
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            pattern_ids = [item["pattern_id"] for item in findings]
            self.assertIn("url_query_secret", pattern_ids)
        finally:
            os.remove(temp_path)

    def test_console_log_secret(self):
        env_var = "".join(["OPENAI_", "API_KEY"])
        with tempfile.NamedTemporaryFile("w+", suffix=".ts", delete=False) as f:
            f.write(f'console.log("Connecting with key:", process.env.{env_var});\n')
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            pattern_ids = [item["pattern_id"] for item in findings]
            self.assertIn("console_log_secret", pattern_ids)
        finally:
            os.remove(temp_path)

    def test_docker_hardcoded_env(self):
        with tempfile.NamedTemporaryFile("w+", suffix="Dockerfile", delete=False) as f:
            dummy_key = "".join(["sk-", "proj-", "9876543210zyxwvutsrqponmlkjihgfedcba"])
            f.write(f'ENV OPENAI_API_KEY="{dummy_key}"\n')
            temp_path = f.name
        try:
            findings = scan_file_for_code_patterns(temp_path)
            pattern_ids = [item["pattern_id"] for item in findings]
            self.assertIn("docker_hardcoded_env", pattern_ids)
        finally:
            os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
