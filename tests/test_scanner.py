"""Tests for HideTheKey secret detector and scanner."""

import os
import tempfile
import unittest
import subprocess
from hide_the_key.secret_detector import (
    calculate_entropy,
    mask_secret,
    is_safe_filename,
    scan_file_for_secrets,
    is_false_positive,
)
from hide_the_key.git_checker import (
    is_git_repo,
    check_git_ignore,
    is_file_tracked,
)
from hide_the_key.scanner import scan_directory
from hide_the_key.fix import add_to_gitignore, untrack_file


class TestSecretDetector(unittest.TestCase):
    def test_mask_secret(self):
        raw = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
        masked = mask_secret(raw)
        self.assertTrue(masked.startswith("sk-pro"))
        self.assertTrue(masked.endswith("wxyz"))
        self.assertIn("...****...", masked)
        self.assertNotIn("1234567890", masked)

    def test_safe_filenames(self):
        self.assertTrue(is_safe_filename(".env.example"))
        self.assertTrue(is_safe_filename("config.template"))
        self.assertTrue(is_safe_filename(".env.sample"))
        self.assertFalse(is_safe_filename(".env"))
        self.assertFalse(is_safe_filename(".env.local"))

    def test_false_positive_filter(self):
        # Placeholder should be filtered
        self.assertTrue(is_false_positive("dummy_key_here", "API_KEY = 'dummy_key_here'", "generic_secret_assignment"))
        self.assertTrue(is_false_positive("your_api_key_here", "const key = 'your_api_key_here';", "generic_secret_assignment"))
        self.assertTrue(is_false_positive("some_key", "const key = process.env.API_KEY;", "generic_secret_assignment"))

    def test_scan_file_for_secrets(self):
        # Construct keys at runtime to avoid false-positive self-scan
        google_val = "".join(["AIzaSy", "BvG52q7W9tKl8OpNmX1_yZvQt94sAbCdE"])
        gh_val = "".join(["ghp_", "1A2B3C4D5E6F7G8H9J0K1L2M3N4P5Q6R7S8T"])

        with tempfile.NamedTemporaryFile("w+", suffix=".py", delete=False) as f:
            f.write(f"""
# Target script
api_client_key = "{google_val}"
github_token = "{gh_val}"
""")
            temp_path = f.name

        try:
            findings = scan_file_for_secrets(temp_path)
            rule_ids = [item["rule_id"] for item in findings]
            self.assertIn("google_api_key", rule_ids)
            self.assertIn("github_pat", rule_ids)
            self.assertEqual(len(findings), 2)
        finally:
            os.remove(temp_path)


    def test_various_api_keys(self):
        # Dynamically compose keys
        openai_key = "".join(["sk-", "proj-", "9mNZ918xQ2aKl4WpRt07YuOiJhGfDsAsQweRtyUiOp98760921"])
        anthropic_key = "".join(["sk-", "ant-", "api03-", "mnbvcz8765432109mnbvcz8765432109mnbvcz876543"])
        aws_key = "".join(["AK", "IA", "IOSFODNN7ZTRWSQ2"])
        stripe_key = "".join(["sk_", "live_", "51OzKmLnOpQrStUvWxYz0987654"])
        slack_key = "".join(["xoxb-", "987654321098-9876543210987-", "lkjhgfdsapoiuytrewqzxcvb"])

        content = f"""
openai = "{openai_key}"
anthropic = "{anthropic_key}"
aws_id = "{aws_key}"
stripe = "{stripe_key}"
slack = "{slack_key}"
"""
        with tempfile.NamedTemporaryFile("w+", suffix=".py", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            findings = scan_file_for_secrets(temp_path)
            rule_ids = {item["rule_id"] for item in findings}
            self.assertIn("openai_project_key", rule_ids)
            self.assertIn("anthropic_api_key", rule_ids)
            self.assertIn("aws_access_key", rule_ids)
            self.assertIn("stripe_secret_key", rule_ids)
            self.assertIn("slack_token", rule_ids)
        finally:
            os.remove(temp_path)

    def test_safe_env_example_ignored(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".env.example", delete=False) as f:
            f.write("OPENAI_API_KEY=sk-proj-12345678901234567890\n")
            temp_path = f.name
        try:
            findings = scan_file_for_secrets(temp_path)
            self.assertEqual(len(findings), 0)
        finally:
            os.remove(temp_path)


class TestGitScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.realpath(tempfile.mkdtemp())
        # Initialize a temporary git repository
        subprocess.run(["git", "init"], cwd=self.test_dir, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.name", "TestUser"], cwd=self.test_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.test_dir, check=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_unignored_secret_file(self):
        # Create an untracked, unignored .env file
        env_path = os.path.join(self.test_dir, ".env")
        with open(env_path, "w") as f:
            f.write("SECRET_KEY=123456789\n")

        summary = scan_directory(self.test_dir)
        self.assertEqual(summary.high_count, 1)
        self.assertEqual(summary.issues[0].issue_type, "SECRET_FILE_NOT_IGNORED")

        # Now fix it by adding to .gitignore
        add_to_gitignore(self.test_dir, ".env")
        summary_after = scan_directory(self.test_dir)
        self.assertEqual(summary_after.high_count, 0)
        self.assertEqual(summary_after.safe_count, 1)

    def test_tracked_secret_file(self):
        # Create and git-add a secret file
        key_path = os.path.join(self.test_dir, "server.key")
        key_header = "".join(["-----BEGIN ", "RSA PRIVATE KEY-----"])
        key_footer = "".join(["-----END ", "RSA PRIVATE KEY-----"])
        with open(key_path, "w") as f:
            f.write(f"{key_header}\nMIIEowIBAAKCAQEA...\n{key_footer}\n")

        subprocess.run(["git", "add", "server.key"], cwd=self.test_dir, check=True)

        summary = scan_directory(self.test_dir)
        # Should detect CRITICAL because server.key is tracked and in staged diff
        self.assertGreaterEqual(summary.critical_count, 1)
        issue_types = [i.issue_type for i in summary.issues]
        self.assertIn("SECRET_FILE_TRACKED", issue_types)

        # Untrack using fix helper
        success, _ = untrack_file(self.test_dir, "server.key")
        self.assertTrue(success)
        self.assertFalse(is_file_tracked(self.test_dir, "server.key"))


    def test_git_history_detection(self):
        # Create a secret file and commit it
        secret_file = os.path.join(self.test_dir, ".env.production")
        with open(secret_file, "w") as f:
            f.write("DB_PASSWORD=supersecret\n")

        subprocess.run(["git", "add", ".env.production"], cwd=self.test_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Add production env by mistake"], cwd=self.test_dir, check=True)

        # Delete it locally
        os.remove(secret_file)
        subprocess.run(["git", "add", ".env.production"], cwd=self.test_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Remove env file"], cwd=self.test_dir, check=True)

        # File is not currently present on disk, but exists in git history!
        summary = scan_directory(self.test_dir, check_history=True)
        history_leaks = [i for i in summary.issues if i.issue_type == "GIT_HISTORY_LEAK"]
        self.assertGreaterEqual(len(history_leaks), 1)
        self.assertIn(".env.production", history_leaks[0].file_path)


if __name__ == "__main__":
    unittest.main()
