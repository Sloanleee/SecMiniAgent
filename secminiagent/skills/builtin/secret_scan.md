# secret_scan
Description: Find hardcoded secrets and credential-like assignments.

Use `scan_secrets` for repository-wide checks. Treat private keys, API keys, tokens, passwords, and access keys as sensitive.

Recommend removing the secret from source control, rotating it, and loading it from environment variables or a secret manager.
