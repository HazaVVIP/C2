"""
core/crawler.py
Handles all GitHub API interactions: search, crawl, fetch content.
"""

import time
import base64
import requests
from typing import List, Dict, Optional


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


class GitHubCrawler:
    def __init__(self, token: str, max_repos: int = 50):
        self.token = token
        self.max_repos = max_repos
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHunt-Security-Research/1.0",
        })
        self._request_count = 0

    def _get(self, url: str, params: dict = None) -> Optional[dict]:
        """Make a rate-limit-aware GET request."""
        self._request_count += 1

        # Throttle: GitHub Search API allows 30 req/min (authenticated)
        if self._request_count % 25 == 0:
            print("  [!] Rate limit pause (2s)...")
            time.sleep(2)

        try:
            resp = self.session.get(url, params=params, timeout=15)

            if resp.status_code == 403:
                reset_time = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_time - int(time.time()), 5)
                print(f"  [!] Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                resp = self.session.get(url, params=params, timeout=15)

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            else:
                return None

        except requests.RequestException as e:
            print(f"  [!] Request error: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  SEARCH                                                               #
    # ------------------------------------------------------------------ #

    def search_repositories(self, keyword: str) -> List[Dict]:
        """Search for repositories matching the keyword."""
        results = []
        page = 1

        while len(results) < self.max_repos:
            data = self._get(f"{GITHUB_API}/search/repositories", params={
                "q": keyword,
                "sort": "updated",
                "order": "desc",
                "per_page": 30,
                "page": page,
            })

            if not data or not data.get("items"):
                break

            results.extend(data["items"])
            page += 1

            if len(data["items"]) < 30:
                break

        return results[:self.max_repos]

    def search_code(self, keyword: str) -> List[Dict]:
        """
        Search GitHub code index for the keyword.
        This catches files that mention the keyword directly.
        """
        results = []
        page = 1

        while len(results) < 100:
            data = self._get(f"{GITHUB_API}/search/code", params={
                "q": keyword,
                "per_page": 30,
                "page": page,
            })

            if not data or not data.get("items"):
                break

            results.extend(data["items"])
            page += 1

            if len(data["items"]) < 30 or page > 3:
                break

            time.sleep(1)  # Extra throttle for code search

        return results

    def search_gists(self, keyword: str) -> List[Dict]:
        """Search public gists for the keyword."""
        data = self._get(f"{GITHUB_API}/gists/public", params={
            "per_page": 30
        })
        # Gist search requires full-text search workaround
        # Return empty for now — can be extended with scraping
        return []

    # ------------------------------------------------------------------ #
    #  CRAWL                                                                #
    # ------------------------------------------------------------------ #

    def get_repo_files(self, repo: Dict, path: str = "") -> List[Dict]:
        """
        Recursively get all interesting files in a repository.
        Returns a flat list of file metadata dicts.
        """
        interesting_files = []

        data = self._get(
            f"{GITHUB_API}/repos/{repo['full_name']}/contents/{path}"
        )

        if not data or not isinstance(data, list):
            return []

        for item in data:
            if item["type"] == "file":
                filename = item["name"]
                ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else filename

                if filename in SKIP_FILES:
                    continue

                if (ext in INTERESTING_EXTENSIONS or
                        filename in INTERESTING_EXTENSIONS or
                        self._is_interesting_name(filename)):
                    interesting_files.append(item)

            elif item["type"] == "dir":
                # Recurse into directories (limit depth via naming heuristics)
                if not self._should_skip_dir(item["name"]):
                    sub_files = self.get_repo_files(repo, item["path"])
                    interesting_files.extend(sub_files)

        return interesting_files

    def get_file_content(self, file_info: Dict) -> Optional[str]:
        """Fetch and decode the content of a single file."""
        # If file_info already has content (from code search)
        if file_info.get("content"):
            try:
                return base64.b64decode(file_info["content"]).decode("utf-8", errors="ignore")
            except Exception:
                pass

        # Fetch via API url
        url = file_info.get("url") or file_info.get("git_url")
        if not url:
            return None

        # Skip large files (>500KB)
        if file_info.get("size", 0) > 500_000:
            return None

        data = self._get(url)
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

    # ------------------------------------------------------------------ #
    #  COMMIT HISTORY (deep scan)                                           #
    # ------------------------------------------------------------------ #

    def get_commit_history(self, repo: Dict, max_commits: int = 50) -> List[Dict]:
        """Get recent commits for a repository."""
        data = self._get(
            f"{GITHUB_API}/repos/{repo['full_name']}/commits",
            params={"per_page": max_commits}
        )
        return data if isinstance(data, list) else []

    def get_commit_diff(self, repo: Dict, sha: str) -> Optional[str]:
        """Get the diff/patch of a single commit."""
        url = f"{GITHUB_API}/repos/{repo['full_name']}/commits/{sha}"

        try:
            resp = self.session.get(
                url,
                headers={**self.session.headers, "Accept": "application/vnd.github.v3.diff"},
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.text
        except requests.RequestException:
            pass

        return None

    # ------------------------------------------------------------------ #
    #  HELPERS                                                              #
    # ------------------------------------------------------------------ #

    def _is_interesting_name(self, name: str) -> bool:
        """Check if filename is interesting based on name patterns."""
        interesting_patterns = [
            "secret", "credential", "password", "passwd", "token",
            "apikey", "api_key", "api-key", "auth", "private",
            "config", "setting", "database", "db", "connection",
        ]
        name_lower = name.lower()
        return any(p in name_lower for p in interesting_patterns)

    def _should_skip_dir(self, dirname: str) -> bool:
        """Skip directories that are unlikely to contain credentials."""
        skip_dirs = {
            "node_modules", ".git", "vendor", "dist", "build",
            "__pycache__", ".pytest_cache", "coverage", "docs",
            "test", "tests", "spec", "fixtures", "examples",
        }
        return dirname.lower() in skip_dirs
