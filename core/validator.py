"""
core/validator.py
Validates discovered credentials against their respective APIs.
All public methods are coroutines; call them inside an asyncio event loop.
"""

import asyncio
import logging
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# Possible validation outcomes
VALID = "VALID"
INVALID = "INVALID"
UNKNOWN = "UNKNOWN"
RATE_LIMITED = "RATE_LIMITED"
ERROR = "ERROR"


class CredentialValidator:
    """
    Async validator for discovered credentials.

    Usage::

        validator = CredentialValidator()
        await validator.validate_findings(findings)
        # Each finding now has a "validation_status" key.
    """

    def __init__(self, timeout: int = 10, concurrency: int = 5) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------ #
    #  Public interface                                                     #
    # ------------------------------------------------------------------ #

    async def validate_findings(self, findings: List[Dict]) -> None:
        """
        Validate all HIGH-severity findings in *findings* concurrently.
        Adds a ``validation_status`` key to each finding in-place.
        Unknown-severity findings and those not matching a supported
        validator get ``UNKNOWN`` status without making any network call.
        """
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            tasks = [
                self._validate_one(finding, session) for finding in findings
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------------ #
    #  Internal dispatcher                                                  #
    # ------------------------------------------------------------------ #

    async def _validate_one(
        self, finding: Dict, session: aiohttp.ClientSession
    ) -> None:
        """Dispatch to the right validator and store the result."""
        cred_type = finding.get("type", "").lower()
        value = finding.get("matched_value", "")

        if not value:
            finding["validation_status"] = UNKNOWN
            return

        async with self._sem:
            try:
                if "github" in cred_type:
                    status = await self._validate_github(value, session)
                elif "stripe live secret" in cred_type:
                    status = await self._validate_stripe(value, session)
                elif "slack bot" in cred_type or "slack incoming" in cred_type:
                    status = await self._validate_slack(value, session)
                elif "sendgrid" in cred_type:
                    status = await self._validate_sendgrid(value, session)
                elif "gitlab" in cred_type:
                    status = await self._validate_gitlab(value, session)
                else:
                    status = UNKNOWN
            except Exception as exc:
                logger.debug("Validation error for %s: %s", cred_type, exc)
                status = ERROR

        finding["validation_status"] = status

    # ------------------------------------------------------------------ #
    #  Per-provider validators                                              #
    # ------------------------------------------------------------------ #

    async def _validate_github(
        self, token: str, session: aiohttp.ClientSession
    ) -> str:
        """Call GET /user with the token; returns VALID / INVALID / RATE_LIMITED."""
        try:
            async with session.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {token}",
                    "User-Agent": "GitHunt-Security-Research/1.0",
                },
            ) as resp:
                if resp.status == 200:
                    return VALID
                if resp.status == 401:
                    return INVALID
                if resp.status in {403, 429}:
                    return RATE_LIMITED
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("GitHub validation error: %s", exc)
            return ERROR
        return UNKNOWN

    async def _validate_stripe(
        self, key: str, session: aiohttp.ClientSession
    ) -> str:
        """Call GET /v1/account with the Stripe secret key."""
        try:
            async with session.get(
                "https://api.stripe.com/v1/account",
                headers={"Authorization": f"Bearer {key}"},
            ) as resp:
                if resp.status == 200:
                    return VALID
                if resp.status == 401:
                    return INVALID
                if resp.status == 429:
                    return RATE_LIMITED
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("Stripe validation error: %s", exc)
            return ERROR
        return UNKNOWN

    async def _validate_slack(
        self, token: str, session: aiohttp.ClientSession
    ) -> str:
        """Call POST slack.com/api/auth.test with the Slack token."""
        try:
            async with session.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return VALID if data.get("ok") else INVALID
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("Slack validation error: %s", exc)
            return ERROR
        return UNKNOWN

    async def _validate_sendgrid(
        self, key: str, session: aiohttp.ClientSession
    ) -> str:
        """Call GET /v3/scopes with the SendGrid API key."""
        try:
            async with session.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {key}"},
            ) as resp:
                if resp.status == 200:
                    return VALID
                if resp.status == 401:
                    return INVALID
                if resp.status == 429:
                    return RATE_LIMITED
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("SendGrid validation error: %s", exc)
            return ERROR
        return UNKNOWN

    async def _validate_gitlab(
        self, token: str, session: aiohttp.ClientSession
    ) -> str:
        """Call GET /api/v4/user with the GitLab personal token."""
        try:
            async with session.get(
                "https://gitlab.com/api/v4/user",
                headers={"PRIVATE-TOKEN": token},
            ) as resp:
                if resp.status == 200:
                    return VALID
                if resp.status == 401:
                    return INVALID
                if resp.status == 429:
                    return RATE_LIMITED
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("GitLab validation error: %s", exc)
            return ERROR
        return UNKNOWN
