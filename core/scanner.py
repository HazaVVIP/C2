"""
core/scanner.py
Pattern-based credential scanner.
Detects secrets, tokens, API keys, and sensitive data in file content.
"""

import re
from typing import List, Dict
from datetime import datetime


# ------------------------------------------------------------------ #
#  PATTERN LIBRARY                                                     #
# ------------------------------------------------------------------ #
#  Each pattern has:
#    name     : human-readable label
#    regex    : compiled regex
#    severity : HIGH / MEDIUM / LOW
#    entropy  : minimum Shannon entropy (optional, 0 = skip)
# ------------------------------------------------------------------ #

PATTERNS = [
    # ── Cloud Providers ───────────────────────────────────────────── #
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        "severity": "HIGH",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"),
        "severity": "HIGH",
    },
    {
        "name": "GCP Service Account Key",
        "regex": re.compile(r'"type":\s*"service_account"'),
        "severity": "HIGH",
    },
    {
        "name": "Azure Storage Account Key",
        "regex": re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})"),
        "severity": "HIGH",
    },

    # ── Payment & Finance ─────────────────────────────────────────── #
    {
        "name": "Stripe Live Secret Key",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "severity": "HIGH",
    },
    {
        "name": "Stripe Test Secret Key",
        "regex": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        "severity": "MEDIUM",
    },
    {
        "name": "PayPal / Braintree Token",
        "regex": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        "severity": "HIGH",
    },

    # ── Communication Services ────────────────────────────────────── #
    {
        "name": "Twilio Account SID",
        "regex": re.compile(r"AC[a-zA-Z0-9]{32}"),
        "severity": "MEDIUM",
    },
    {
        "name": "Twilio Auth Token",
        "regex": re.compile(r"(?i)twilio.{0,20}['\"]([a-f0-9]{32})['\"]"),
        "severity": "HIGH",
    },
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}"),
        "severity": "HIGH",
    },
    {
        "name": "Mailgun API Key",
        "regex": re.compile(r"key-[0-9a-zA-Z]{32}"),
        "severity": "HIGH",
    },

    # ── Version Control & CI/CD ───────────────────────────────────── #
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
    },
    {
        "name": "GitHub OAuth Token",
        "regex": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
    },
    {
        "name": "GitHub App Token",
        "regex": re.compile(r"(ghu|ghs|ghr)_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
    },
    {
        "name": "GitLab Personal Token",
        "regex": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "severity": "HIGH",
    },

    # ── Database ──────────────────────────────────────────────────── #
    {
        "name": "Database Connection String (Generic)",
        "regex": re.compile(
            r"(?i)(mysql|postgres|postgresql|mongodb|mssql|redis|oracle)"
            r"://[^:\s]+:[^@\s]+@[^\s]+"
        ),
        "severity": "HIGH",
    },
    {
        "name": "MongoDB URI",
        "regex": re.compile(r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s]+"),
        "severity": "HIGH",
    },

    # ── Private Keys & Certificates ───────────────────────────────── #
    {
        "name": "RSA Private Key",
        "regex": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "severity": "HIGH",
    },
    {
        "name": "EC Private Key",
        "regex": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "severity": "HIGH",
    },
    {
        "name": "PGP Private Key",
        "regex": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "severity": "HIGH",
    },
    {
        "name": "OpenSSH Private Key",
        "regex": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "severity": "HIGH",
    },

    # ── Generic Secrets ───────────────────────────────────────────── #
    {
        "name": "Generic API Key Assignment",
        "regex": re.compile(
            r"(?i)(?:api[_\-]?key|apikey|access[_\-]?key)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"
        ),
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Secret Assignment",
        "regex": re.compile(
            r"(?i)(?:secret|password|passwd|pwd)"
            r"\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"
        ),
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Token Assignment",
        "regex": re.compile(
            r"(?i)(?:token|auth_token|access_token)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]"
        ),
        "severity": "MEDIUM",
    },
    {
        "name": "JWT Token",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "MEDIUM",
    },

    # ── Indonesia-specific ────────────────────────────────────────── #
    {
        "name": "Midtrans Server Key",
        "regex": re.compile(r"(?:Mid-server-|SB-Mid-server-)[A-Za-z0-9_-]{36,}"),
        "severity": "HIGH",
    },
    {
        "name": "Midtrans Client Key",
        "regex": re.compile(r"(?:Mid-client-|SB-Mid-client-)[A-Za-z0-9_-]{36,}"),
        "severity": "MEDIUM",
    },
    {
        "name": "Xendit API Key",
        "regex": re.compile(r"xnd_(?:production|development)_[A-Za-z0-9]{40,}"),
        "severity": "HIGH",
    },
    {
        "name": "DOKU API Key",
        "regex": re.compile(r"(?i)doku.{0,20}['\"]([A-Za-z0-9]{32,})['\"]"),
        "severity": "HIGH",
    },
]

# Lines to ignore (common false positives)
IGNORE_PATTERNS = [
    re.compile(r"(?i)example|placeholder|your[_-]?key|replace[_-]?me|xxx+|dummy"),
    re.compile(r"(?i)<your|{{.*}}|\$\{.*\}|%s|%d|\*{4,}"),
    re.compile(r"^#"),  # Comments
]


class CredentialScanner:
    def __init__(self):
        self.patterns = PATTERNS

    def scan(
        self,
        content: str,
        source: str,
        repo: str,
        filename: str
    ) -> List[Dict]:
        """
        Scan file content for credential patterns.
        Returns a list of finding dicts.
        """
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and obvious comments/placeholders
            if not line.strip() or self._is_false_positive(line):
                continue

            for pattern in self.patterns:
                match = pattern["regex"].search(line)
                if match:
                    # Extract the matched value (group 1 if available)
                    matched_value = match.group(1) if match.lastindex else match.group(0)

                    finding = {
                        "id": f"{repo}:{filename}:{line_num}",
                        "type": pattern["name"],
                        "severity": pattern["severity"],
                        "repo": repo,
                        "filename": filename,
                        "line_number": line_num,
                        "line_content": self._redact(line.strip()),
                        "matched_value": self._redact(matched_value),
                        "source_url": source,
                        "timestamp": datetime.utcnow().isoformat(),
                    }

                    findings.append(finding)

        return self._deduplicate(findings)

    def _is_false_positive(self, line: str) -> bool:
        """Check if a line is likely a false positive."""
        return any(p.search(line) for p in IGNORE_PATTERNS)

    def _redact(self, value: str) -> str:
        """Partially redact sensitive values for safe logging."""
        if len(value) <= 8:
            return "***"
        # Show first 4 and last 4 chars
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on matched value."""
        seen = set()
        unique = []
        for f in findings:
            key = (f["repo"], f["filename"], f["matched_value"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
