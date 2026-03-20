#!/usr/bin/env python3
"""
GitHunt - GitHub Credential Exposure Crawler
Usage: python githunt.py --keyword "komdigi.go.id" --token YOUR_GITHUB_TOKEN
       python githunt.py --keyword "komdigi.go.id"  # token otomatis dipakai setelah disimpan
"""

import argparse
import getpass
import os
import sys
from typing import Optional
from core.crawler import GitHubCrawler
from core.scanner import CredentialScanner
from core.reporter import Reporter

TOKEN_PATH = os.path.join(os.path.expanduser("~"), ".githunt_token")


def load_saved_token(token_path: str = TOKEN_PATH) -> Optional[str]:
    try:
        with open(token_path, "r") as handle:
            token = handle.read().strip()
            return token or None
    except FileNotFoundError:
        return None
    except OSError:
        print("[!] Gagal membaca token tersimpan. Periksa izin atau isi file.", file=sys.stderr)
        return None


def save_token(token: str, token_path: str = TOKEN_PATH) -> None:
    try:
        token_dir = os.path.dirname(token_path)
        if not os.path.isdir(token_dir):
            try:
                os.makedirs(token_dir, exist_ok=True)
            except OSError:
                print("[!] Gagal membuat direktori token.", file=sys.stderr)
                return

        with open(token_path, "w") as handle:
            handle.write(token.strip())
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            print("[!] Peringatan: Tidak bisa mengatur permission file token.", file=sys.stderr)
            print("[!] File token mungkin dapat dibaca oleh pengguna lain.", file=sys.stderr)
        print(f"[*] Token disimpan di {token_path}")
    except OSError:
        print("[!] Gagal menyimpan token.", file=sys.stderr)


def resolve_token(passed_token: Optional[str]) -> str:
    saved_token = load_saved_token()

    if passed_token:
        if passed_token != saved_token:
            save_token(passed_token)
        return passed_token

    if saved_token:
        return saved_token

    if not sys.stdin.isatty():
        print("[!] Token belum tersimpan. Jalankan dengan --token atau jalankan interaktif.", file=sys.stderr)
        sys.exit(1)

    try:
        token = getpass.getpass(f"GitHub token (disimpan di {TOKEN_PATH}): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Input token dibatalkan.", file=sys.stderr)
        sys.exit(1)

    if not token:
        print("[!] Token kosong. Jalankan ulang dan masukkan token.", file=sys.stderr)
        sys.exit(1)

    save_token(token)
    return token


def banner():
    print(r"""
  _____ _ _   _   _             _   
 / ____(_) | | | | |           | |  
| |  __ _| |_| |_| |_   _ _ __ | |_ 
| | |_ | | __|  _  | | | | '_ \| __|
| |__| | | |_| | | | |_| | | | | |_ 
 \_____|_|\__|_| |_|\__,_|_| |_|\__|
                                     
  GitHub Credential Exposure Crawler
  For authorized security research only.
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="GitHunt - Crawl GitHub for exposed credentials"
    )
    parser.add_argument(
        "--keyword", "-k",
        required=True,
        help="Keyword to search (e.g. 'komdigi.go.id', 'mycompany.com')"
    )
    parser.add_argument(
        "--token", "-t",
        required=False,
        help="GitHub Personal Access Token (disimpan otomatis setelah input pertama)"
    )
    parser.add_argument(
        "--output", "-o",
        default="json",
        choices=["json", "csv", "html"],
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=50,
        help="Max repositories to crawl (default: 50)"
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan (includes commit history)"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate if found credentials are still active"
    )
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    print(f"[*] Target keyword : {args.keyword}")
    print(f"[*] Max repos      : {args.max_repos}")
    print(f"[*] Deep scan      : {args.deep}")
    print(f"[*] Validate creds : {args.validate}")
    print("-" * 50)

    token = resolve_token(args.token)

    # Initialize components
    crawler = GitHubCrawler(token=token, max_repos=args.max_repos)
    scanner = CredentialScanner()
    reporter = Reporter(output_format=args.output)

    # Step 1: Search GitHub for related repositories
    print(f"\n[1/3] Searching GitHub for: '{args.keyword}'...")
    repos = crawler.search_repositories(args.keyword)
    code_results = crawler.search_code(args.keyword)

    print(f"  → Found {len(repos)} repositories")
    print(f"  → Found {len(code_results)} code matches")

    # Step 2: Crawl each repository
    print(f"\n[2/3] Crawling repositories...")
    all_findings = []

    for i, repo in enumerate(repos, 1):
        print(f"  [{i}/{len(repos)}] Scanning: {repo['full_name']}")
        
        # Get file tree from repo
        files = crawler.get_repo_files(repo)
        
        for file_info in files:
            content = crawler.get_file_content(file_info)
            if content:
                findings = scanner.scan(
                    content=content,
                    source=file_info["html_url"],
                    repo=repo["full_name"],
                    filename=file_info["path"]
                )
                all_findings.extend(findings)

        # Deep scan: commit history
        if args.deep:
            commits = crawler.get_commit_history(repo)
            for commit in commits:
                diff = crawler.get_commit_diff(repo, commit["sha"])
                if diff:
                    findings = scanner.scan(
                        content=diff,
                        source=f"{repo['html_url']}/commit/{commit['sha']}",
                        repo=repo["full_name"],
                        filename=f"[commit] {commit['sha'][:8]}"
                    )
                    all_findings.extend(findings)

    # Also scan direct code search results
    for result in code_results:
        content = crawler.get_file_content(result)
        if content:
            findings = scanner.scan(
                content=content,
                source=result.get("html_url", ""),
                repo=result.get("repository", {}).get("full_name", "unknown"),
                filename=result.get("path", "unknown")
            )
            all_findings.extend(findings)

    # Step 3: Report results
    print(f"\n[3/3] Generating report...")
    print(f"  → Total findings: {len(all_findings)}")

    high   = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low    = [f for f in all_findings if f["severity"] == "LOW"]

    print(f"  → HIGH   : {len(high)}")
    print(f"  → MEDIUM : {len(medium)}")
    print(f"  → LOW    : {len(low)}")

    output_file = reporter.save(all_findings, keyword=args.keyword)
    print(f"\n[✓] Report saved to: {output_file}")


if __name__ == "__main__":
    main()
