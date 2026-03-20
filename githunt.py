#!/usr/bin/env python3
"""
GitHunt - GitHub Credential Exposure Crawler
Usage: python githunt.py --keyword "komdigi.go.id" --token YOUR_GITHUB_TOKEN
       python githunt.py --keyword "komdigi.go.id"  # token otomatis dipakai setelah disimpan
       python githunt.py --keyword "example" -u https://github.com/owner/repo
       python githunt.py --keyword "example" -g "https://ghp_TOKEN@github.com/owner/repo.git"
       python githunt.py --keywords-file targets.txt --output sarif
"""

import argparse
import asyncio
import errno
import getpass
import logging
import os
import sys
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from core.crawler import GitHubCrawler
from core.scanner import CredentialScanner
from core.reporter import Reporter
from core.validator import CredentialValidator

TOKEN_PATH = os.path.join(os.path.expanduser("~"), ".githunt_token")
console = Console()


# ------------------------------------------------------------------ #
#  Token management                                                    #
# ------------------------------------------------------------------ #

def load_saved_token(token_path: str = TOKEN_PATH) -> Optional[str]:
    try:
        with open(token_path, "r", encoding="utf-8") as handle:
            token = handle.read().strip()
            return token or None
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            message = "Tidak punya izin untuk membaca token tersimpan."
        elif exc.errno == errno.EIO:
            message = "Terjadi kesalahan I/O saat membaca token tersimpan."
        else:
            message = "Terjadi kesalahan saat membaca token tersimpan."
        console.print(f"[bold red][!][/bold red] {message}")
        return None


def save_token(token: str, token_path: str = TOKEN_PATH) -> None:
    try:
        with open(token_path, "w", encoding="utf-8") as handle:
            handle.write(token.strip())
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            console.print("[yellow][!] Peringatan: Tidak bisa mengatur permission file token.[/yellow]")
            console.print("[yellow][!] File token mungkin dapat dibaca oleh pengguna lain.[/yellow]")
        console.print(f"[green][*][/green] Token disimpan di {token_path}")
    except OSError:
        console.print("[bold red][!] Gagal menyimpan token.[/bold red]")


def resolve_token(passed_token: Optional[str]) -> str:
    saved_token = load_saved_token()

    if passed_token:
        if passed_token != saved_token:
            save_token(passed_token)
        return passed_token

    if saved_token:
        return saved_token

    if not sys.stdin.isatty():
        console.print("[bold red][!] Token belum tersimpan. Jalankan dengan --token atau jalankan interaktif.[/bold red]")
        sys.exit(1)

    try:
        token = getpass.getpass("GitHub token (akan disimpan secara lokal): ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[bold red][!] Input token dibatalkan.[/bold red]")
        sys.exit(1)

    if not token:
        console.print("[bold red][!] Token kosong. Jalankan ulang dan masukkan token.[/bold red]")
        sys.exit(1)

    save_token(token)
    return token


# ------------------------------------------------------------------ #
#  URL / git-config helpers                                            #
# ------------------------------------------------------------------ #

def parse_repo_fullname(url_or_slug: str) -> Optional[str]:
    """
    Accept various GitHub repo references and return ``owner/repo``.

    Supported formats:
    - ``owner/repo``
    - ``https://github.com/owner/repo``
    - ``https://github.com/owner/repo.git``
    - ``git@github.com:owner/repo.git``
    - ``https://TOKEN@github.com/owner/repo.git``  (git-config style)
    """
    s = url_or_slug.strip()

    # SSH format: git@github.com:owner/repo.git
    if s.startswith("git@"):
        # git@github.com:owner/repo.git  →  owner/repo
        colon_idx = s.find(":")
        if colon_idx != -1:
            path = s[colon_idx + 1:]
            path = path.removesuffix(".git")
            parts = path.split("/")
            if len(parts) == 2 and all(parts):
                return "/".join(parts)
        return None

    # HTTPS / plain slug
    if "://" in s:
        parsed = urlparse(s)
        path = parsed.path.lstrip("/").removesuffix(".git")
    else:
        path = s.removesuffix(".git")

    parts = path.split("/")
    if len(parts) >= 2 and all(parts[:2]):
        return f"{parts[0]}/{parts[1]}"

    return None


def extract_from_git_config_url(git_config_url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a git remote URL that may contain an embedded GitHub token and
    return ``(token, owner/repo)``.

    Supported URL forms found in ``.git/config``:
    - ``https://ghp_TOKEN@github.com/owner/repo.git``
    - ``https://oauth2:ghp_TOKEN@github.com/owner/repo.git``
    - ``https://x-access-token:ghp_TOKEN@github.com/owner/repo.git``

    Returns ``(None, None)`` if no token could be extracted.
    """
    try:
        parsed = urlparse(git_config_url)
    except Exception:
        return None, None

    # Token lives in the password field (oauth2:TOKEN) or username field (TOKEN@host)
    token = parsed.password or parsed.username or None

    # Derive repo fullname from the URL path
    repo = parse_repo_fullname(git_config_url)

    return token, repo


# ------------------------------------------------------------------ #
#  Keywords helpers                                                    #
# ------------------------------------------------------------------ #

def load_keywords_file(path: str) -> List[str]:
    """
    Read a plain-text file with one keyword per line.
    Empty lines and lines starting with ``#`` are ignored.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
    except OSError as exc:
        console.print(f"[bold red][!] Gagal membaca keywords file '{path}': {exc}[/bold red]")
        sys.exit(1)


# ------------------------------------------------------------------ #
#  Banner                                                              #
# ------------------------------------------------------------------ #

def banner() -> None:
    console.print(r"""
  _____ _ _   _   _             _   
 / ____(_) | | | | |           | |  
| |  __ _| |_| |_| |_   _ _ __ | |_ 
| | |_ | | __|  _  | | | | '_ \| __|
| |__| | | |_| | | | |_| | | | | |_ 
 \_____|_|\__|_| |_|\__,_|_| |_|\__|
                                     
  [bold green]GitHub Credential Exposure Crawler[/bold green]
  [dim]For authorized security research only.[/dim]
""")


# ------------------------------------------------------------------ #
#  CLI                                                                 #
# ------------------------------------------------------------------ #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GitHunt - Crawl GitHub for exposed credentials"
    )

    kw_group = parser.add_mutually_exclusive_group(required=True)
    kw_group.add_argument(
        "--keyword", "-k",
        help="Keyword to search (e.g. 'komdigi.go.id', 'mycompany.com')",
    )
    kw_group.add_argument(
        "--keywords-file",
        metavar="FILE",
        help=(
            "Path to a plain-text file with one keyword per line. "
            "Empty lines and lines starting with '#' are ignored. "
            "Cannot be combined with --keyword."
        ),
    )

    parser.add_argument(
        "--token", "-t",
        required=False,
        help="GitHub Personal Access Token (disimpan otomatis setelah input pertama)",
    )
    parser.add_argument(
        "--url", "-u",
        required=False,
        metavar="REPO_URL",
        help=(
            "Target a specific GitHub repository instead of running a broad search. "
            "Accepts: 'owner/repo', 'https://github.com/owner/repo', or any GitHub repo URL."
        ),
    )
    parser.add_argument(
        "--git-config-url", "-g",
        required=False,
        metavar="GIT_REMOTE_URL",
        help=(
            "Git remote URL with an embedded access token (as found in .git/config). "
            "Example: 'https://ghp_TOKEN@github.com/owner/repo.git'. "
            "The token and target repo are extracted automatically from this URL."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        default="json",
        choices=["json", "csv", "html", "sarif", "markdown"],
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to write report files into (default: current directory)",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=50,
        help="Max repositories to crawl (default: 50)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent async HTTP requests (default: 10)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan (includes commit history)",
    )
    parser.add_argument(
        "--scan-gists",
        action="store_true",
        help="Also search public GitHub Gists for the keyword",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate if found credentials are still active",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    return parser.parse_args()


# ------------------------------------------------------------------ #
#  Async main scan logic                                               #
# ------------------------------------------------------------------ #

async def run_scan(
    args: argparse.Namespace,
    token: str,
    keyword: str,
    target_repo: Optional[str] = None,
) -> List[dict]:
    """Main async scanning coroutine — returns all findings.

    When *target_repo* is set (``owner/repo``), the broad repository/code search
    is skipped and only that single repository is scanned.
    """
    scanner = CredentialScanner()
    all_findings: List[dict] = []

    async with GitHubCrawler(
        token=token,
        max_repos=args.max_repos,
        concurrency=args.concurrency,
    ) as crawler:

        # ── Step 1: Search / resolve repos ────────────────────────── #
        if target_repo:
            console.print(
                f"\n[bold cyan][1/3][/bold cyan] Resolving target repository: "
                f"[yellow]'{target_repo}'[/yellow]..."
            )
            repo = await crawler.get_single_repo(target_repo)
            if not repo:
                console.print(
                    f"[bold red][!][/bold red] Repository '{target_repo}' not found "
                    f"or token lacks access."
                )
                return []
            repos = [repo]
            code_results: List[dict] = []
            console.print(f"  → Scanning 1 repository: [bold]{repo['full_name']}[/bold]")
        else:
            console.print(f"\n[bold cyan][1/3][/bold cyan] Searching GitHub for: [yellow]'{keyword}'[/yellow]...")

            search_tasks = [
                crawler.search_repositories(keyword),
                crawler.search_code(keyword),
            ]
            if args.scan_gists:
                search_tasks.append(crawler.search_gists(keyword))

            search_results = await asyncio.gather(*search_tasks)
            repos = search_results[0]
            code_results = search_results[1]
            gist_results: List[dict] = search_results[2] if args.scan_gists else []

            console.print(f"  → Found [bold]{len(repos)}[/bold] repositories")
            console.print(f"  → Found [bold]{len(code_results)}[/bold] code matches")
            if args.scan_gists:
                console.print(f"  → Found [bold]{len(gist_results)}[/bold] gist matches")

        # ── Step 2: Crawl ──────────────────────────────────────────── #
        console.print(f"\n[bold cyan][2/3][/bold cyan] Crawling repositories...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            repo_task = progress.add_task("Scanning repos...", total=len(repos))

            for repo in repos:
                progress.update(repo_task, description=f"[cyan]{repo['full_name'][:50]}[/cyan]")

                # Collect interesting files
                files = await crawler.get_repo_files(repo)

                # Fetch all file contents concurrently
                if files:
                    contents = await crawler.get_files_content_batch(files)
                    for file_info, content in zip(files, contents):
                        if content:
                            findings = scanner.scan(
                                content=content,
                                source=file_info["html_url"],
                                repo=repo["full_name"],
                                filename=file_info["path"],
                            )
                            all_findings.extend(findings)

                # Deep scan: commit history
                if args.deep:
                    commits = await crawler.get_commit_history(repo)
                    diff_tasks = [
                        crawler.get_commit_diff(repo, c["sha"]) for c in commits
                    ]
                    raw_diffs = await asyncio.gather(*diff_tasks, return_exceptions=True)
                    for commit, diff in zip(commits, raw_diffs):
                        if isinstance(diff, BaseException) or not diff:
                            continue
                        findings = scanner.scan(
                            content=diff,
                            source=f"{repo['html_url']}/commit/{commit['sha']}",
                            repo=repo["full_name"],
                            filename=f"[commit] {commit['sha'][:8]}",
                        )
                        all_findings.extend(findings)

                progress.advance(repo_task)

        # Also scan direct code-search results
        if code_results:
            contents = await crawler.get_files_content_batch(code_results)
            for result, content in zip(code_results, contents):
                if content:
                    findings = scanner.scan(
                        content=content,
                        source=result.get("html_url", ""),
                        repo=result.get("repository", {}).get("full_name", "unknown"),
                        filename=result.get("path", "unknown"),
                    )
                    all_findings.extend(findings)

        # Scan gist results
        if args.scan_gists and gist_results:
            gist_contents = await crawler.get_files_content_batch(gist_results)
            for result, content in zip(gist_results, gist_contents):
                if content:
                    findings = scanner.scan(
                        content=content,
                        source=result.get("html_url", ""),
                        repo=result.get("repository", {}).get("full_name", "gist"),
                        filename=result.get("path", "unknown"),
                    )
                    all_findings.extend(findings)

    # ── Optional: Validate credentials ────────────────────────────── #
    if args.validate and all_findings:
        console.print(f"\n[bold cyan][2.5/3][/bold cyan] Validating {len(all_findings)} findings...")
        validator = CredentialValidator()
        await validator.validate_findings(all_findings)
        valid_count = sum(
            1 for f in all_findings if f.get("validation_status") == "VALID"
        )
        console.print(f"  → [bold green]{valid_count}[/bold green] credentials confirmed VALID")

    return all_findings


# ------------------------------------------------------------------ #
#  Entry point                                                         #
# ------------------------------------------------------------------ #

def main() -> None:
    banner()
    args = parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False)],
    )

    # ── Resolve keywords ──────────────────────────────────────────── #
    if args.keywords_file:
        keywords = load_keywords_file(args.keywords_file)
        if not keywords:
            console.print("[bold red][!] keywords-file is empty.[/bold red]")
            sys.exit(1)
        console.print(f"[green][*][/green] Loaded [bold]{len(keywords)}[/bold] keywords from '{args.keywords_file}'")
    else:
        keywords = [args.keyword]

    # ── Resolve target repo and token from --git-config-url / --url ── #
    target_repo: Optional[str] = None
    git_config_token: Optional[str] = None
    extracted_repo: Optional[str] = None

    if args.git_config_url:
        git_config_token, extracted_repo = extract_from_git_config_url(args.git_config_url)
        if not git_config_token:
            console.print(
                "[bold red][!][/bold red] Tidak dapat mengekstrak token dari URL git-config. "
                "Pastikan URL dalam format: https://TOKEN@github.com/owner/repo.git"
            )
            sys.exit(1)
        console.print(
            f"[green][*][/green] Token diekstrak dari git-config URL "
            f"(panjang: {len(git_config_token)} karakter)"
        )

    if args.url:
        # --url explicitly overrides any repo extracted from --git-config-url
        parsed_repo = parse_repo_fullname(args.url)
        if not parsed_repo:
            console.print(
                f"[bold red][!][/bold red] Tidak dapat mem-parsing repo dari URL: '{args.url}'. "
                "Gunakan format: owner/repo atau https://github.com/owner/repo"
            )
            sys.exit(1)
        target_repo = parsed_repo
        console.print(f"[green][*][/green] Target repo: [yellow]{target_repo}[/yellow]")
    elif extracted_repo:
        # Fall back to repo derived from --git-config-url when --url is not set
        target_repo = extracted_repo
        console.print(f"[green][*][/green] Target repo diekstrak dari git-config URL: [yellow]{target_repo}[/yellow]")

    # Token precedence: --token > --git-config-url token > saved/interactive
    if args.token is not None:
        token = resolve_token(args.token)
    elif git_config_token is not None:
        token = resolve_token(git_config_token)
    else:
        token = resolve_token(None)

    console.print(f"[*] Keywords        : [yellow]{', '.join(keywords)}[/yellow]")
    if target_repo:
        console.print(f"[*] Target repo     : [yellow]{target_repo}[/yellow]")
    console.print(f"[*] Max repos       : {args.max_repos}")
    console.print(f"[*] Concurrency     : {args.concurrency}")
    console.print(f"[*] Deep scan       : {args.deep}")
    console.print(f"[*] Scan gists      : {args.scan_gists}")
    console.print(f"[*] Validate creds  : {args.validate}")
    console.print(f"[*] Output format   : {args.output}")
    console.print(f"[*] Output dir      : {args.output_dir}")
    console.print("-" * 50)

    # Run scans — one per keyword, accumulate all findings
    all_findings: List[dict] = []
    for keyword in keywords:
        if len(keywords) > 1:
            console.print(f"\n[bold magenta]▶ Keyword: '{keyword}'[/bold magenta]")
        keyword_findings = asyncio.run(
            run_scan(args, token, keyword=keyword, target_repo=target_repo)
        )
        all_findings.extend(keyword_findings)

    # ── Step 3: Report ─────────────────────────────────────────────── #
    console.print(f"\n[bold cyan][3/3][/bold cyan] Generating report...")

    high   = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low    = [f for f in all_findings if f["severity"] == "LOW"]

    summary = Table(show_header=True, header_style="bold magenta")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")
    if args.validate:
        summary.add_column("Validated VALID", justify="right")
        high_valid   = sum(1 for f in high   if f.get("validation_status") == "VALID")
        medium_valid = sum(1 for f in medium if f.get("validation_status") == "VALID")
        low_valid    = sum(1 for f in low    if f.get("validation_status") == "VALID")
        summary.add_row("[red]HIGH[/red]",        str(len(high)),   str(high_valid))
        summary.add_row("[yellow]MEDIUM[/yellow]", str(len(medium)), str(medium_valid))
        summary.add_row("[blue]LOW[/blue]",        str(len(low)),    str(low_valid))
        summary.add_row("TOTAL",                   str(len(all_findings)),
                        str(high_valid + medium_valid + low_valid))
    else:
        summary.add_row("[red]HIGH[/red]",   str(len(high)))
        summary.add_row("[yellow]MEDIUM[/yellow]", str(len(medium)))
        summary.add_row("[blue]LOW[/blue]",  str(len(low)))
        summary.add_row("TOTAL", str(len(all_findings)))
    console.print(summary)

    # Use the first keyword as the report label when multiple keywords are used
    report_keyword = keywords[0] if len(keywords) == 1 else f"multi_{len(keywords)}_keywords"
    reporter = Reporter(output_format=args.output, output_dir=args.output_dir)
    output_file = reporter.save(all_findings, keyword=report_keyword)
    console.print(f"\n[bold green][✓][/bold green] Report saved to: [underline]{output_file}[/underline]")


if __name__ == "__main__":
    main()

