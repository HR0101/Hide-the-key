---
name: hide-the-key
description: Autonomous secret leak auditor & .gitignore enforcer. Verifies that API keys, sensitive tokens, and .env files are properly excluded from Git before committing or pushing to GitHub.
---

# HideTheKey Skill: Autonomous Secret Leak Prevention

Use this skill whenever you are about to:
1. Commit or push code changes to GitHub.
2. Initialize a new project or create config files like `.env`, `credentials.json`, or service account keys.
3. Review an existing codebase for exposed API keys, private keys, or improper `.gitignore` setups.

## Execution Commands

### 1. Pre-commit Audit (Targeted Project)
Run this check inside the repository root before staging or committing changes:
```bash
hide-the-key
# Or using the direct path:
/Users/Rhara/Hide-the-key/bin/hide-the-key
```

### 2. Auto-fix Unignored Files
If unignored secrets or `.env` files are reported:
```bash
hide-the-key --fix
```
This automatically appends unignored files to `.gitignore` and untracks any inadvertently staged files via `git rm --cached`.

### 3. CI / Non-interactive Verification
For automated pipelines or scripting:
```bash
hide-the-key --ci --json
```

## Protocol for Autonomous Agents

1. **Gatekeeping**: Never push to remote (`git push`) if `hide-the-key` exits with code 1.
2. **Environment Variables**:
   - When an agent detects a `HARDCODED_KEY` issue, refactor the code to read from `os.environ` / `process.env` and place the real value in `.env` (which must be in `.gitignore`).
   - **Frontend Danger**: NEVER prefix backend secrets with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_`. These prefixes expose the secret to client-side browser bundles.
   - **No Hardcoded Fallbacks**: Never write `process.env.KEY || 'raw_key'` or `os.getenv('KEY', 'raw_key')`. Require environment variables explicitly.
   - **No Secret Logging**: Never `console.log(process.env.SECRET_KEY)` or `print(api_key)` in code.
3. **Commit History Scrubbing**: If `hide-the-key --history` reports a committed secret, alert the user immediately to rotate the compromised credential.
