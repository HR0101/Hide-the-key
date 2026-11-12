"""Constants and detection signatures for HideTheKey."""

import re

# Directories to skip by default when scanning recursively
DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env_virt",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".output",
    "Pods",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".terraform",
    ".cargo",
    ".gradle",
    ".idea",
    ".vscode",
    "CVS",
    ".svn",
    ".hg",
}

# Directories to skip when scanning the entire home/system directory
GLOBAL_SCAN_IGNORE_DIRS = {
    # System / OS
    "Library",
    "System",
    "Applications",
    "Public",
    ".Trash",
    # Package & cache stores
    ".npm",
    ".yarn",
    ".pnpm-store",
    ".cargo",
    ".rustup",
    ".gem",
    ".bundle",
    ".cache",
    ".cocoapods",
    ".gradle",
    ".m2",
    ".nuget",
    ".local/share/Trash",
    # Virtual machines & containers
    ".docker",
    ".orbstack",
    "VirtualBox VMs",
    # IDE & Browser caches
    ".vscode/extensions",
    # Common big project artifacts
    "node_modules",
    "venv",
    ".venv",
    "vendor",
    "target",
    "dist",
    "build",
    "Pods",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}
MAX_SCAN_FILE_SIZE = 5 * 1024 * 1024

# Files that should be protected and typically ignored by .gitignore
SECRET_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".htpasswd",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "google-services.json",
}

# File extensions that usually contain sensitive keys/certs
SECRET_FILE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".pkcs12",
    ".keystore",
    ".jks",
    ".ovpn",
    ".kdbx",
}

# Regex patterns for files that are likely secrets
SECRET_FILE_REGEXES = [
    re.compile(r"^\.env(\.[a-zA-Z0-9_\-]+)?$", re.IGNORECASE),
    re.compile(r"^serviceAccountKey.*\.json$", re.IGNORECASE),
    re.compile(r"^client_secret.*\.json$", re.IGNORECASE),
    re.compile(r"^firebase.*\.json$", re.IGNORECASE),
    re.compile(r"^id_(?:rsa|ed25519|ecdsa|dsa)(?:\..+)?$", re.IGNORECASE),
    re.compile(r".*credentials.*\.json$", re.IGNORECASE),
    re.compile(r".*secret.*\.ya?ml$", re.IGNORECASE),
]

# Patterns for safe/template files that are meant to be committed
SAFE_FILE_SUFFIXES = [
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".defaults",
    ".test",
    ".mock",
]

# Additional unwanted files that often leak or clutter Git
SUSPICIOUS_UNWANTED_FILES = [
    (".DS_Store", "macOS metadata file (should not be committed to GitHub)"),
    ("Thumbs.db", "Windows thumbnail cache (should not be committed)"),
    ("*.sqlite", "SQLite database file (may contain sensitive user data)"),
    ("*.sqlite3", "SQLite3 database file (may contain sensitive user data)"),
    ("*.sql.gz", "SQL database backup file"),
    ("*.dump", "Database dump file"),
]

# High-precision patterns for API keys and tokens in code
SECRET_SIGNATURES = [
    {
        "id": "openai_api_key",
        "name": "OpenAI API Key",
        "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{48})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "openai_project_key",
        "name": "OpenAI Project API Key",
        "pattern": re.compile(r"\b(sk-proj-[a-zA-Z0-9_\-]{20,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "openai_admin_key",
        "name": "OpenAI Admin API Key",
        "pattern": re.compile(r"\b(sk-admin-[a-zA-Z0-9_\-]{20,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "anthropic_api_key",
        "name": "Anthropic Claude API Key",
        "pattern": re.compile(r"\b(sk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{32,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "google_api_key",
        "name": "Google / Gemini API Key",
        "pattern": re.compile(r"\b(AIzaSy[0-9A-Za-z_\-]{33})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Z0-9])"),
        "severity": "CRITICAL",
    },
    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token (classic)",
        "pattern": re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "github_fine_grained_pat",
        "name": "GitHub Fine-Grained Personal Access Token",
        "pattern": re.compile(r"\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "github_oauth",
        "name": "GitHub OAuth Access Token",
        "pattern": re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "github_app_token",
        "name": "GitHub App / Server Token",
        "pattern": re.compile(r"\b(gh[su]_[a-zA-Z0-9]{36})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "slack_token",
        "name": "Slack Bot/User Token",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "slack_webhook",
        "name": "Slack Incoming Webhook URL",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "severity": "HIGH",
    },
    {
        "id": "stripe_secret_key",
        "name": "Stripe Secret / Restricted Key",
        "pattern": re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "discord_bot_token",
        "name": "Discord Bot Token",
        "pattern": re.compile(r"(?<![a-zA-Z0-9_\-])([MN][A-Za-z\d]{23,26}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,38})(?![a-zA-Z0-9_\-])"),
        "severity": "CRITICAL",
    },
    {
        "id": "telegram_bot_token",
        "name": "Telegram Bot Token",
        "pattern": re.compile(r"(?<![0-9])([0-9]{9,10}:[a-zA-Z0-9_\-]{35})(?![a-zA-Z0-9_\-])"),
        "severity": "CRITICAL",
    },
    {
        "id": "huggingface_token",
        "name": "Hugging Face Access Token",
        "pattern": re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "groq_api_key",
        "name": "Groq API Key",
        "pattern": re.compile(r"\b(gsk_[a-zA-Z0-9]{48,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "resend_api_key",
        "name": "Resend API Key",
        "pattern": re.compile(r"\b(re_[a-zA-Z0-9]{24,})\b"),
        "severity": "HIGH",
    },
    {
        "id": "supabase_key",
        "name": "Supabase Service/Secret Key",
        "pattern": re.compile(r"\b(sbp_[a-zA-Z0-9]{40})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "perplexity_api_key",
        "name": "Perplexity API Key",
        "pattern": re.compile(r"\b(pplx-[a-zA-Z0-9]{48})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "sendgrid_api_key",
        "name": "SendGrid API Key",
        "pattern": re.compile(r"\b(SG\.[a-zA-Z0-9_\-\.]{66})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "twilio_api_key",
        "name": "Twilio API Key",
        "pattern": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        "severity": "HIGH",
    },
    {
        "id": "mailgun_api_key",
        "name": "Mailgun API Key",
        "pattern": re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        "severity": "HIGH",
    },
    {
        "id": "npm_token",
        "name": "NPM Access Token",
        "pattern": re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "pypi_token",
        "name": "PyPI API Token",
        "pattern": re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b"),
        "severity": "CRITICAL",
    },
    {
        "id": "private_key",
        "name": "Private Key (RSA / EC / OpenSSH / PGP)",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "severity": "CRITICAL",
    },
    {
        "id": "generic_secret_assignment",
        "name": "Hardcoded Secret / API Key Assignment",
        "pattern": re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']"
        ),
        "severity": "HIGH",
    },
]

# Words that indicate dummy, test, or example values
FALSE_POSITIVE_SUBSTRINGS = [
    "example",
    "dummy",
    "placeholder",
    "sample",
    "changeme",
    "your_",
    "my_",
    "test_",
    "_test",
    "mock",
    "xxxx",
    "12345",
    "abcdef",
    "fake",
    "<your",
    "${",
    "process.env",
    "os.environ",
    "os.getenv",
    "config(",
    "env(",
    "env[",
    "secret_here",
    "api_key_here",
    "token_here",
    "your-api-key",
    "insert-key-here",
]

# Dangerous public environment variable prefixes (exposed to browser bundles)
PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "PUBLIC_")

# Sensitive terms that must NEVER be combined with public prefixes
SENSITIVE_KEYWORD_REGEX = re.compile(
    r"(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|AWS|SECRET|PRIVATE|TOKEN|PASSWORD|API_KEY|SERVICE_ROLE|BACKEND)",
    re.IGNORECASE
)

# Patterns for dangerous code patterns and references
DANGEROUS_CODE_PATTERNS = [
    {
        "id": "env_fallback_leak",
        "name": "Hardcoded Secret Fallback in Environment Lookup",
        "pattern": re.compile(
            r"""(?:process\.env\.[A-Z0-9_]+|os\.(?:getenv|environ\.get)\s*\(['"][A-Z0-9_]+['"]\))\s*(?:\|\||\?\?|,)\s*['"]([a-zA-Z0-9_\-/.+=]{16,})['"]"""
        ),
        "severity": "CRITICAL",
        "description": "Environment variable lookup has a hardcoded secret fallback value.",
        "suggestion": "Remove the hardcoded default value and require the environment variable at runtime.",
    },
    {
        "id": "url_embedded_credentials",
        "name": "Embedded Credentials in URL",
        "pattern": re.compile(
            r"""https?://([a-zA-Z0-9_.-]+:[^@\s/]+)@[a-zA-Z0-9_.-]+"""
        ),
        "severity": "CRITICAL",
        "description": "URL contains basic-auth username:password or token embedded directly.",
        "suggestion": "Use authorization headers (e.g. 'Authorization: Bearer <token>') instead of URL credentials.",
    },
    {
        "id": "url_query_secret",
        "name": "API Key / Secret in URL Query String",
        "pattern": re.compile(
            r"""(?i)https?://[^\s'"?]+\?[^\s'"]*(?:api[_-]?key|key|secret|token|access[_-]?token)=([a-zA-Z0-9_\-]{16,})"""
        ),
        "severity": "CRITICAL",
        "description": "API Key is hardcoded inside URL query parameters.",
        "suggestion": "Pass API keys via HTTP headers, or load the key dynamically from environment variables.",
    },
    {
        "id": "console_log_secret",
        "name": "Logging Secret / Credential to Output",
        "pattern": re.compile(
            r"""(?i)(?:console\.log|print|logger\.(?:info|debug|warn|error))\s*\([^)]*\b(process\.env\.[A-Z0-9_]*(?:KEY|SECRET|TOKEN|AUTH|PASS)[A-Z0-9_]*|api[_-]?key|secret[_-]?key|auth[_-]?token)\b[^)]*\)"""
        ),
        "severity": "HIGH",
        "description": "Secret or sensitive environment variable is being logged to console/logger.",
        "suggestion": "Remove log statements that print secret values to prevent leaks in logs, CI, or APM.",
    },
    {
        "id": "docker_hardcoded_env",
        "name": "Hardcoded Secret in Docker ENV/ARG Instruction",
        "pattern": re.compile(
            r"""(?i)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:KEY|SECRET|TOKEN|AUTH|PASSWORD)[A-Z0-9_]*\s*=\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?"""
        ),
        "severity": "CRITICAL",
        "description": "Secret value is hardcoded in Dockerfile ENV or ARG instruction.",
        "suggestion": "Use Docker BuildKit secrets (--secret) or pass secrets at runtime instead of bake-in.",
    },
]
