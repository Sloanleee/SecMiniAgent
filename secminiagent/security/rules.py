from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True, slots=True)
class SecurityRule:
    rule_id: str
    title: str
    severity: str
    pattern: Pattern[str]
    recommendation: str
    category: str


SECRET_RULES = [
    SecurityRule(
        "SECRET_PRIVATE_KEY",
        "Private key material detected",
        "high",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
        "Remove private keys from the repository and rotate the exposed key.",
        "secret",
    ),
    SecurityRule(
        "SECRET_OPENAI_KEY",
        "OpenAI-style API key detected",
        "high",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
        "Move API keys to a secret manager or local .env file ignored by git, then rotate the key.",
        "secret",
    ),
    SecurityRule(
        "SECRET_AWS_ACCESS_KEY",
        "AWS access key id detected",
        "high",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Remove the credential from source control and rotate it in AWS IAM.",
        "secret",
    ),
    SecurityRule(
        "SECRET_ASSIGNMENT",
        "Sensitive-looking assignment detected",
        "medium",
        re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}"),
        "Avoid hardcoded secrets. Load sensitive values from environment variables or a vault.",
        "secret",
    ),
]


INSECURE_PATTERN_RULES = [
    SecurityRule(
        "PY_EVAL_EXEC",
        "Dynamic code execution detected",
        "high",
        re.compile(r"\b(eval|exec)\s*\("),
        "Avoid eval/exec on untrusted input. Use explicit parsing or a safe interpreter.",
        "code",
    ),
    SecurityRule(
        "PY_SUBPROCESS_SHELL_TRUE",
        "subprocess with shell=True detected",
        "high",
        re.compile(r"\bsubprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True"),
        "Pass argv as a list and keep shell=False unless the command is fully trusted.",
        "code",
    ),
    SecurityRule(
        "PY_PICKLE_LOADS",
        "Unsafe pickle deserialization detected",
        "high",
        re.compile(r"\bpickle\.(loads|load)\s*\("),
        "Do not unpickle untrusted data. Use JSON or a constrained serializer.",
        "code",
    ),
    SecurityRule(
        "WEAK_HASH_MD5_SHA1",
        "Weak hash algorithm detected",
        "medium",
        re.compile(r"\bhashlib\.(md5|sha1)\s*\("),
        "Use SHA-256 or stronger hashing, and use password hashing functions for passwords.",
        "code",
    ),
    SecurityRule(
        "PLAINTEXT_HTTP",
        "Plaintext HTTP URL detected",
        "medium",
        re.compile(r"['\"]http://[^'\"]+['\"]"),
        "Use HTTPS for network requests unless plaintext transport is explicitly justified.",
        "code",
    ),
    SecurityRule(
        "SQL_STRING_CONCAT",
        "Possible SQL string concatenation detected",
        "medium",
        re.compile(r"(?i)\b(select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b.{0,80}(\+|%|format\()"),
        "Use parameterized queries instead of string concatenation.",
        "code",
    ),
    SecurityRule(
        "PATH_TRAVERSAL_HINT",
        "Path traversal pattern detected",
        "medium",
        re.compile(r"\.\./|\.\.\\\\"),
        "Normalize and validate paths against an allowed workspace root.",
        "code",
    ),
]


ALL_RULES = SECRET_RULES + INSECURE_PATTERN_RULES
