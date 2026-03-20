#!/usr/bin/env python3
"""
GitHunt - GitHub Credential Exposure Crawler
Usage: python githunt.py --keyword "komdigi.go.id" --token YOUR_GITHUB_TOKEN
       python githunt.py --keyword "komdigi.go.id"  # token otomatis dipakai setelah disimpan
"""

import argparse
import asyncio
import errno
import getpass
import logging
import os
import sys
from typing import List, Optional

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
    parser.add_argument(
        "--keyword", "-k",
        required=True,
        help="Keyword to search (e.g. 'komdigi.go.id', 'mycompany.com')",
    )
    parser.add_argument(
        "--token", "-t",
        required=False,
        help="GitHub Personal Access Token (disimpan otomatis setelah input pertama)",
    )
    parser.add_argument(
        "--output", "-o",
        default="json",
        choices=["json", "csv", "html"],
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

async def run_scan(args: argparse.Namespace, token: str) -> List[dict]:
    """Main async scanning coroutine — returns all findings."""
    scanner = CredentialScanner()
    all_findings: List[dict] = []

    async with GitHubCrawler(
        token=token,
        max_repos=args.max_repos,
        concurrency=args.concurrency,
    ) as crawler:

        # ── Step 1: Search ─────────────────────────────────────────── #
        console.print(f"\n[bold cyan][1/3][/bold cyan] Searching GitHub for: [yellow]'{args.keyword}'[/yellow]...")

        repos, code_results = await asyncio.gather(
            crawler.search_repositories(args.keyword),
            crawler.search_code(args.keyword),
        )

        console.print(f"  → Found [bold]{len(repos)}[/bold] repositories")
        console.print(f"  → Found [bold]{len(code_results)}[/bold] code matches")

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

    console.print(f"[*] Target keyword  : [yellow]{args.keyword}[/yellow]")
    console.print(f"[*] Max repos       : {args.max_repos}")
    console.print(f"[*] Concurrency     : {args.concurrency}")
    console.print(f"[*] Deep scan       : {args.deep}")
    console.print(f"[*] Validate creds  : {args.validate}")
    console.print(f"[*] Output dir      : {args.output_dir}")
    console.print("-" * 50)

    token = resolve_token(args.token)

    # Run the async scan
    all_findings = asyncio.run(run_scan(args, token))

    # ── Step 3: Report ─────────────────────────────────────────────── #
    console.print(f"\n[bold cyan][3/3][/bold cyan] Generating report...")

    high   = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low    = [f for f in all_findings if f["severity"] == "LOW"]

    summary = Table(show_header=True, header_style="bold magenta")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")
    summary.add_row("[red]HIGH[/red]",   str(len(high)))
    summary.add_row("[yellow]MEDIUM[/yellow]", str(len(medium)))
    summary.add_row("[blue]LOW[/blue]",  str(len(low)))
    summary.add_row("TOTAL", str(len(all_findings)))
    console.print(summary)

    reporter = Reporter(output_format=args.output, output_dir=args.output_dir)
    output_file = reporter.save(all_findings, keyword=args.keyword)
    console.print(f"\n[bold green][✓][/bold green] Report saved to: [underline]{output_file}[/underline]")


if __name__ == "__main__":
    main()
