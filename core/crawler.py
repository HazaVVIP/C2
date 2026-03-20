"""
core/crawler.py
Handles all GitHub API interactions using aiohttp + asyncio.
All public methods are coroutines; call them inside an asyncio event loop.
"""

import asyncio
import base64
import logging
import time
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# File extensions worth scanning for credentials
INTERESTING_EXTENSIONS = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
    ".json", ".xml", ".properties",
    ".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".cs",
    ".sh", ".bash", ".zsh", ".ps1",
    ".pem", ".key", ".p12", ".pfx", ".cer",
    "Dockerfile", "docker-compose.yml",
    ".htpasswd", ".npmrc", ".gradle",
}

# Files to skip (too large or irrelevant)
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "composer.lock",
    "Gemfile.lock", "go.sum",
}

# Directories unlikely to contain credentials
SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".pytest_cache", "coverage", "docs",
    "test", "tests", "spec", "fixtures", "examples",
}


class GitHubCrawler:
    """
    Async GitHub crawler built on aiohttp.

    Usage (inside an async context)::

        async with GitHubCrawler(token="ghp_...") as crawler:
            repos = await crawler.search_repositories("komdigi.go.id")
            ...

    Or use the module-level helper :func:`run_crawler` for one-shot usage.
    """

    def __init__(
        self,
        token: str,
        max_repos: int = 50,
        concurrency: int = 10,
    ) -> None:
        self.token = token
        self.max_repos = max_repos
        self.concurrency = concurrency
        self._session: Optional[aiohttp.ClientSession] = None
        # Semaphore created lazily in __aenter__ / _ensure_session
        self._sem: Optional[asyncio.Semaphore] = None

    # ------------------------------------------------------------------ #
    #  Context-manager helpers                                              #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "GitHubCrawler":
        await self._ensure_session()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        """Create the aiohttp session and semaphore if they don't exist yet."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=40, connect=10)
            connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"token {self.token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "GitHunt-Security-Research/1.0",
                },
                timeout=timeout,
                connector=connector,
            )
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.concurrency)

    async def close(self) -> None:
        """Close the underlying aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------ #
    #  Internal GET                                                         #
    # ------------------------------------------------------------------ #

    async def _get(
        self,
        url: str,
        params: Optional[dict] = None,
        accept: Optional[str] = None,
    ) -> Optional[dict]:
        """Rate-limit-aware async GET; returns parsed JSON or None."""
        await self._ensure_session()
        assert self._session is not None
        assert self._sem is not None

        headers: dict = {}
        if accept:
            headers["Accept"] = accept

        async with self._sem:
            for attempt in range(3):
                try:
                    async with self._session.get(
                        url, params=params, headers=headers
                    ) as resp:
                        # Proactive rate-limit check
                        remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))
                        if remaining <= 2:
                            reset_ts = int(
                                resp.headers.get("X-RateLimit-Reset", time.time() + 60)
                            )
                            wait = max(reset_ts - int(time.time()), 5)
                            logger.warning(
                                "Rate limit nearly exhausted — waiting %ds...", wait
                            )
                            await asyncio.sleep(wait)

                        if resp.status == 403:
                            reset_ts = int(
                                resp.headers.get("X-RateLimit-Reset", time.time() + 60)
                            )
                            wait = max(reset_ts - int(time.time()), 5)
                            logger.warning("Rate limited (403) — waiting %ds...", wait)
                            await asyncio.sleep(wait)
                            continue  # retry

                        if resp.status == 401:
                            logger.error(
                                "Authentication failed (401). Check your GitHub token."
                            )
                            return None

                        if resp.status == 422:
                            logger.warning(
                                "Unprocessable entity (422) for %s — query may be invalid.",
                                url,
                            )
                            return None

                        if resp.status == 200:
                            return await resp.json()

                        logger.debug(
                            "Non-200 response %d for %s", resp.status, url
                        )
                        return None

                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    logger.warning(
                        "Request error for %s (attempt %d/3): %s", url, attempt + 1, exc
                    )
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt)

        return None

    async def _get_text(self, url: str, accept: str) -> Optional[str]:
        """GET a URL and return the raw text body (for diffs)."""
        await self._ensure_session()
        assert self._session is not None
        assert self._sem is not None

        async with self._sem:
            try:
                async with self._session.get(
                    url, headers={"Accept": accept}
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.warning("Error fetching text from %s: %s", url, exc)

        return None

    # ------------------------------------------------------------------ #
    #  SEARCH                                                               #
    # ------------------------------------------------------------------ #

    async def get_single_repo(self, full_name: str) -> Optional[Dict]:
        """
        Fetch metadata for a single repository by its ``owner/repo`` name.
        Returns the repo dict on success, or *None* if the repo could not be
        fetched (e.g. it does not exist or the token lacks access).
        """
        data = await self._get(f"{GITHUB_API}/repos/{full_name}")
        return data if isinstance(data, dict) else None

    async def search_repositories(self, keyword: str) -> List[Dict]:
        """Search for repositories matching the keyword."""
        results: List[Dict] = []
        page = 1

        while len(results) < self.max_repos:
            data = await self._get(
                f"{GITHUB_API}/search/repositories",
                params={
                    "q": keyword,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 30,
                    "page": page,
                },
            )

            if not data or not data.get("items"):
                break

            results.extend(data["items"])
            page += 1

            if len(data["items"]) < 30:
                break

        return results[: self.max_repos]

    async def search_code(self, keyword: str) -> List[Dict]:
        """Search GitHub code index for the keyword."""
        results: List[Dict] = []
        page = 1

        while len(results) < 100:
            data = await self._get(
                f"{GITHUB_API}/search/code",
                params={"q": keyword, "per_page": 30, "page": page},
            )

            if not data or not data.get("items"):
                break

            results.extend(data["items"])
            page += 1

            if len(data["items"]) < 30 or page > 3:
                break

            await asyncio.sleep(1)  # extra throttle for code search

        return results

    async def search_gists(self, keyword: str) -> List[Dict]:
        """
        Search public gists for the keyword via the code-search API.
        Returns file metadata dicts (same shape as code search items).
        """
        from urllib.parse import urlparse

        data = await self._get(
            f"{GITHUB_API}/search/code",
            params={"q": f"{keyword} fork:false", "per_page": 30},
        )
        if not data:
            return []

        gist_results = []
        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            try:
                host = urlparse(html_url).hostname or ""
            except Exception:
                host = ""
            if host == "gist.github.com" or host.endswith(".gist.github.com"):
                gist_results.append(item)
        return gist_results

    # ------------------------------------------------------------------ #
    #  CRAWL                                                                #
    # ------------------------------------------------------------------ #

    async def get_repo_files(
        self, repo: Dict, path: str = ""
    ) -> List[Dict]:
        """
        Recursively collect all interesting files in a repository.
        Returns a flat list of file-metadata dicts.
        """
        data = await self._get(
            f"{GITHUB_API}/repos/{repo['full_name']}/contents/{path}"
        )

        if not data or not isinstance(data, list):
            return []

        interesting: List[Dict] = []
        sub_tasks = []

        for item in data:
            if item["type"] == "file":
                filename = item["name"]
                ext = (
                    "." + filename.rsplit(".", 1)[-1] if "." in filename else filename
                )
                if filename in SKIP_FILES:
                    continue
                if (
                    ext in INTERESTING_EXTENSIONS
                    or filename in INTERESTING_EXTENSIONS
                    or self._is_interesting_name(filename)
                ):
                    interesting.append(item)

            elif item["type"] == "dir":
                if not self._should_skip_dir(item["name"]):
                    sub_tasks.append(self.get_repo_files(repo, item["path"]))

        # Recurse into sub-directories concurrently
        if sub_tasks:
            sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
            for result in sub_results:
                if isinstance(result, list):
                    interesting.extend(result)
                elif isinstance(result, Exception):
                    logger.debug("Error recursing into sub-dir: %s", result)

        return interesting

    async def get_file_content(self, file_info: Dict) -> Optional[str]:
        """Fetch and decode the content of a single file."""
        # Inline content already present (code-search results)
        if file_info.get("content"):
            try:
                return base64.b64decode(file_info["content"]).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                pass

        url = file_info.get("url") or file_info.get("git_url")
        if not url:
            return None

        if file_info.get("size", 0) > 500_000:
            logger.debug(
                "Skipping large file %s (%d bytes)",
                file_info.get("path"),
                file_info.get("size", 0),
            )
            return None

        data = await self._get(url)
        if not data:
            return None

        encoding = data.get("encoding", "")
        content = data.get("content", "")

        if encoding == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="ignore")
            except Exception:
                return None

        return content or None

    async def get_files_content_batch(
        self, files: List[Dict]
    ) -> List[Optional[str]]:
        """
        Fetch all file contents concurrently via asyncio.gather.
        Returns a list aligned with *files*; failed fetches produce None.
        """
        raw = await asyncio.gather(
            *[self.get_file_content(f) for f in files],
            return_exceptions=True,
        )
        results: List[Optional[str]] = []
        for item in raw:
            if isinstance(item, BaseException):
                logger.debug("File fetch error (suppressed): %s", item)
                results.append(None)
            else:
                results.append(item)
        return results

    # ------------------------------------------------------------------ #
    #  COMMIT HISTORY (deep scan)                                           #
    # ------------------------------------------------------------------ #

    async def get_commit_history(
        self, repo: Dict, max_commits: int = 50
    ) -> List[Dict]:
        """Get recent commits for a repository."""
        data = await self._get(
            f"{GITHUB_API}/repos/{repo['full_name']}/commits",
            params={"per_page": max_commits},
        )
        return data if isinstance(data, list) else []

    async def get_commit_diff(self, repo: Dict, sha: str) -> Optional[str]:
        """Get the unified diff of a single commit."""
        url = f"{GITHUB_API}/repos/{repo['full_name']}/commits/{sha}"
        return await self._get_text(url, accept="application/vnd.github.v3.diff")

    # ------------------------------------------------------------------ #
    #  HELPERS                                                              #
    # ------------------------------------------------------------------ #

    def _is_interesting_name(self, name: str) -> bool:
        interesting_patterns = [
            "secret", "credential", "password", "passwd", "token",
            "apikey", "api_key", "api-key", "auth", "private",
            "config", "setting", "database", "db", "connection",
        ]
        return any(p in name.lower() for p in interesting_patterns)

    def _should_skip_dir(self, dirname: str) -> bool:
        return dirname.lower() in SKIP_DIRS
