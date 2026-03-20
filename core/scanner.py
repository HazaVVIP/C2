"""
core/scanner.py
Pattern-based credential scanner.
Detects secrets, tokens, API keys, and sensitive data in file content.
"""

import math
import re
from typing import List, Dict, Optional
from datetime import datetime


# ------------------------------------------------------------------ #
#  PATTERN LIBRARY                                                     #
# ------------------------------------------------------------------ #
#  Each pattern has:
#    name        : human-readable label
#    regex       : compiled regex
#    severity    : HIGH / MEDIUM / LOW
#    min_entropy : minimum Shannon entropy for the captured group
#                  (0 = skip entropy check)
# ------------------------------------------------------------------ #

PATTERNS = [
    # ── Cloud Providers ───────────────────────────────────────────── #
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        "severity": "HIGH",
        "min_entropy": 3.0,
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "GCP Service Account Key",
        "regex": re.compile(r'"type":\s*"service_account"'),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "Azure Storage Account Key",
        "regex": re.compile(
            r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;"
            r"AccountKey=([A-Za-z0-9+/=]{88})"
        ),
        "severity": "HIGH",
        "min_entropy": 4.5,
    },

    # ── Payment & Finance ─────────────────────────────────────────── #
    {
        "name": "Stripe Live Secret Key",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Stripe Publishable Key",
        "regex": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "Stripe Test Secret Key",
        "regex": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "PayPal / Braintree Token",
        "regex": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        "severity": "HIGH",
        "min_entropy": 3.0,
    },

    # ── Communication Services ────────────────────────────────────── #
    {
        "name": "Twilio Account SID",
        # Negative lookbehind prevents matching mid-base64 strings
        # (e.g. sha512 npm integrity hashes that contain "AC" as a substring)
        "regex": re.compile(r"(?<![A-Za-z0-9/+])(AC[a-zA-Z0-9]{32})(?![A-Za-z0-9/+=])"),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "Twilio Auth Token",
        "regex": re.compile(r"(?i)twilio.{0,20}['\"]([a-f0-9]{32})['\"]"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Mailgun API Key",
        "regex": re.compile(r"key-[0-9a-zA-Z]{32}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Slack Bot / App Token",
        "regex": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Slack Incoming Webhook URL",
        "regex": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "severity": "HIGH",
        "min_entropy": 3.0,
    },
    {
        "name": "Discord Bot Token",
        "regex": re.compile(r"[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Discord Webhook URL",
        "regex": re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{60,68}"
        ),
        "severity": "HIGH",
        "min_entropy": 3.0,
    },
    {
        "name": "Telegram Bot Token",
        "regex": re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Version Control & CI/CD ───────────────────────────────────── #
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "GitHub OAuth Token",
        "regex": re.compile(r"gho_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "GitHub App Token",
        "regex": re.compile(r"(ghu|ghs|ghr)_[A-Za-z0-9]{36}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "GitLab Personal Token",
        "regex": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "npm Auth Token",
        "regex": re.compile(r"(?i)(?://registry\.npmjs\.org/:_authToken|npm_token)\s*=\s*([A-Za-z0-9\-_]{36,})"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "CircleCI Personal API Token",
        "regex": re.compile(r"(?i)circleci.{0,20}['\"]([A-Za-z0-9]{40})['\"]"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Cloud Platforms ───────────────────────────────────────────── #
    {
        "name": "Heroku API Key",
        "regex": re.compile(r"(?i)heroku.{0,20}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "DigitalOcean Personal Access Token",
        "regex": re.compile(r"dop_v1_[A-Za-z0-9]{64}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "DigitalOcean OAuth Token",
        "regex": re.compile(r"doo_v1_[A-Za-z0-9]{64}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Cloudflare API Token",
        "regex": re.compile(r"(?i)cloudflare.{0,20}['\"]([A-Za-z0-9_\-]{40})['\"]"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Firebase API Key",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "Firebase Service Account",
        "regex": re.compile(r'"auth_uri":\s*"https://accounts\.google\.com/o/oauth2/auth"'),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "Shopify API Key",
        "regex": re.compile(r"shpat_[A-Za-z0-9]{32}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Shopify Shared Secret",
        "regex": re.compile(r"shpss_[A-Za-z0-9]{32}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Database ──────────────────────────────────────────────────── #
    {
        "name": "Database Connection String (Generic)",
        "regex": re.compile(
            r"(?i)(mysql|postgres|postgresql|mongodb|mssql|redis|oracle)"
            r"://[^:\s]+:[^@\s]+@[^\s]+"
        ),
        "severity": "HIGH",
        "min_entropy": 2.5,
    },
    {
        "name": "MongoDB URI",
        "regex": re.compile(r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s]+"),
        "severity": "HIGH",
        "min_entropy": 2.5,
    },

    # ── Private Keys & Certificates ───────────────────────────────── #
    {
        "name": "RSA Private Key",
        "regex": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "EC Private Key",
        "regex": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "PGP Private Key",
        "regex": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "OpenSSH Private Key",
        "regex": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "severity": "HIGH",
        "min_entropy": 0,
    },
    {
        "name": "PKCS8 Private Key",
        "regex": re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "severity": "HIGH",
        "min_entropy": 0,
    },

    # ── Generic Secrets ───────────────────────────────────────────── #
    {
        "name": "Generic API Key Assignment",
        "regex": re.compile(
            r"(?i)(?:api[_\-]?key|apikey|access[_\-]?key)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"
        ),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "Generic Secret Assignment",
        "regex": re.compile(
            r"(?i)(?:secret|password|passwd|pwd)"
            r"\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"
        ),
        "severity": "MEDIUM",
        "min_entropy": 3.0,
    },
    {
        "name": "Generic Token Assignment",
        "regex": re.compile(
            r"(?i)(?:token|auth_token|access_token)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]"
        ),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "JWT Token",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "MEDIUM",
        "min_entropy": 0,
    },

    # ── Indonesia-specific ────────────────────────────────────────── #
    {
        "name": "Midtrans Server Key",
        "regex": re.compile(r"(?:Mid-server-|SB-Mid-server-)[A-Za-z0-9_-]{36,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Midtrans Client Key",
        "regex": re.compile(r"(?:Mid-client-|SB-Mid-client-)[A-Za-z0-9_-]{36,}"),
        "severity": "MEDIUM",
        "min_entropy": 3.5,
    },
    {
        "name": "Xendit API Key",
        "regex": re.compile(r"xnd_(?:production|development)_[A-Za-z0-9]{40,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "DOKU API Key",
        "regex": re.compile(r"(?i)doku.{0,20}['\"]([A-Za-z0-9]{32,})['\"]"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── AI / ML Providers ─────────────────────────────────────────── #
    {
        "name": "OpenAI API Key",
        "regex": re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "OpenAI API Key (new format)",
        "regex": re.compile(r"sk-proj-[A-Za-z0-9_-]{50,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Anthropic API Key",
        "regex": re.compile(r"sk-ant-[A-Za-z0-9_-]{93,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Hugging Face API Token",
        "regex": re.compile(r"hf_[A-Za-z0-9]{34,}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Observability & Monitoring ────────────────────────────────── #
    {
        "name": "Datadog API Key",
        "regex": re.compile(
            r"(?i)datadog.{0,20}['\"]([A-Za-z0-9]{32})['\"]"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Datadog App Key",
        "regex": re.compile(
            r"(?i)dd.app.key.{0,20}['\"]([A-Za-z0-9]{40})['\"]"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "New Relic API Key",
        "regex": re.compile(r"NRAK-[A-Z0-9]{27}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "New Relic License Key",
        "regex": re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{40}NRAL(?![A-Za-z0-9])"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Grafana API Key",
        "regex": re.compile(r"eyJrIjoi[A-Za-z0-9+/=]{40,}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "PagerDuty API Key",
        "regex": re.compile(
            r"(?i)pagerduty.{0,20}['\"]([A-Za-z0-9+/]{20,})['\"]"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Identity & Access Management ──────────────────────────────── #
    {
        "name": "Okta API Token",
        "regex": re.compile(r"00[A-Za-z0-9_-]{40}"),
        "severity": "HIGH",
        "min_entropy": 4.0,
    },
    {
        "name": "Atlassian API Token",
        "regex": re.compile(
            r"(?i)atlassian.{0,20}['\"]([A-Za-z0-9_\-]{24,})['\"]"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },

    # ── Infrastructure / DevOps ───────────────────────────────────── #
    {
        "name": "HashiCorp Vault Token",
        # Negative lookahead (?![A-Za-z0-9.@]) prevents matching subdomain labels
        # such as s.abcdefghijklmnopqrstuvwxyz.twitter.com that appear in bug-bounty
        # scope / domain list files.  Every character inside a domain label is
        # followed by another alphanumeric or dot, so regex backtracking can never
        # produce a match — unlike (?!\.[A-Za-z0-9]) which only checks for a dot.
        "regex": re.compile(r"(?<![A-Za-z0-9_])((?:hvs|s)\.[A-Za-z0-9]{24,})(?![A-Za-z0-9.@])"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Linear API Key",
        "regex": re.compile(r"lin_api_[A-Za-z0-9]{40}"),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Azure Client Secret",
        "regex": re.compile(
            r"(?i)(?:client.?secret|clientsecret)\s*[:=]\s*['\"]([A-Za-z0-9~._\-]{30,})['\"]"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
    {
        "name": "Alibaba Cloud AccessKey ID",
        "regex": re.compile(r"LTAI[0-9A-Za-z]{16,20}"),
        "severity": "HIGH",
        "min_entropy": 3.0,
    },
    {
        "name": "LaunchDarkly SDK Key",
        "regex": re.compile(
            r"sdk-[A-Za-z0-9_-]{8}-[A-Za-z0-9_-]{4}-"
            r"[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{12}"
        ),
        "severity": "HIGH",
        "min_entropy": 3.5,
    },
]

# Lines to ignore (common false positives)
IGNORE_PATTERNS = [
    re.compile(r"(?i)example|placeholder|your[_-]?key|replace[_-]?me|xxx+|dummy|optional"),
    re.compile(r"(?i)<your|{{.*}}|\$\{.*\}|%s|%d|\*{4,}"),
    re.compile(r'"integrity"\s*:'),  # npm/yarn package-lock integrity hashes
    re.compile(r"^\s*#"),   # Comment lines (handles leading whitespace)
    re.compile(r"^\s*//"),  # JS/Go/Java comment lines
    re.compile(r"^\s*\*"),  # Block comment lines
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


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
                if not match:
                    continue

                # Extract the matched value (group 1 if available)
                matched_value = match.group(1) if match.lastindex else match.group(0)

                # Entropy gate: skip low-entropy matches for patterns that
                # require it (helps eliminate template/placeholder values)
                min_entropy = pattern.get("min_entropy", 0)
                if min_entropy > 0 and shannon_entropy(matched_value) < min_entropy:
                    continue

                finding = {
                    "id": f"{repo}:{filename}:{line_num}",
                    "type": pattern["name"],
                    "severity": pattern["severity"],
                    "repo": repo,
                    "filename": filename,
                    "line_number": line_num,
                    "line_content": line.strip(),
                    "matched_value": matched_value,
                    "source_url": source,
                    "timestamp": datetime.utcnow().isoformat(),
                    "entropy": round(shannon_entropy(matched_value), 2),
                }

                findings.append(finding)

        return self._group_by_source(self._deduplicate(findings))

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
        """Remove duplicate findings based on type, repo, filename, and matched value."""
        seen: set = set()
        unique = []
        for f in findings:
            key = (f["repo"], f["filename"], f["type"], f["matched_value"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _group_by_source(self, findings: List[Dict]) -> List[Dict]:
        """
        Consolidate findings that share the same (repo, filename, type) into
        a single entry.  The first occurrence is used as the representative
        finding; additional occurrences increment the ``count`` field and append
        their line number to ``line_numbers``.

        This prevents files that contain many credentials of the same type
        (e.g. an email dump or a credential list) from flooding the output
        with hundreds of near-identical rows.
        """
        groups: Dict[tuple, Dict] = {}
        for f in findings:
            key = (f["repo"], f["filename"], f["type"])
            if key not in groups:
                entry = dict(f)
                entry["count"] = 1
                entry["line_numbers"] = [f["line_number"]]
                groups[key] = entry
            else:
                groups[key]["count"] += 1
                groups[key]["line_numbers"].append(f["line_number"])
        return list(groups.values())
