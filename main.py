import asyncio
import re
import json
import fnmatch
import csv
from pathlib import Path
from typing import List, Dict
import aiofiles
from prettytable import PrettyTable


def parse_gitignore(gitignore_path: Path) -> List[str]:
    """Reads .gitignore and returns a list of exclusion patterns."""
    ignored_patterns = []
    if gitignore_path.exists():
        with gitignore_path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    ignored_patterns.append(line)
    return ignored_patterns


def should_ignore(path: Path, ignored_patterns: List[str]) -> bool:
    """Checks if a file or folder should be skipped based on .gitignore."""
    for pattern in ignored_patterns:
        if "/" in pattern:  # Handling paths (folders)
            if path.match(pattern) or path.is_relative_to(pattern):
                return True
        elif fnmatch.fnmatch(path.name, pattern):  # Handling wildcard patterns (*, ?)
            return True
    return False


def get_files_to_scan(root_dir: Path, ignored_patterns: List[str]) -> List[Path]:
    """Recursively collects files to scan, skipping ignored ones."""
    return [
        path for path in root_dir.rglob("*") 
        if path.is_file() and not should_ignore(path, ignored_patterns)
    ]


async def find_secrets_in_file(file_path: Path, patterns: List[re.Pattern]) -> List[Dict[str, str]]:
    """Asynchronously scans a file for secrets based on regex patterns."""
    results = []
    try:
        async with aiofiles.open(file_path, "r", encoding="utf-8") as file:
            line_num = 0
            async for line in file:
                line_num += 1
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        results.append({
                            "secret": match.group(),
                            "file": str(file_path),
                            "line": line_num
                        })
    except (UnicodeDecodeError, PermissionError):
        pass  # Skip files that cannot be read

    return results


def print_results_table(results: List[Dict[str, str]]):
    """Prints found secrets in a table format."""
    table = PrettyTable(["Secret", "File", "Line"])
    for result in results:
        table.add_row([result["secret"], result["file"], result["line"]])
    
    print(table)


def save_results_json(results: List[Dict[str, str]], output_file: Path):
    """Saves results to a JSON file."""
    with output_file.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)


def save_results_csv(results: List[Dict[str, str]], output_file: Path):
    """Saves results to a CSV file."""
    with output_file.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["secret", "file", "line"])
        writer.writeheader()
        writer.writerows(results)


async def main():
    root_dir = Path.cwd()  # Use the current directory
    gitignore_path = root_dir / ".gitignore"

    ignored_patterns = parse_gitignore(gitignore_path)
    files_to_scan = get_files_to_scan(root_dir, ignored_patterns)

    print("Skipped files/folders:")
    for pattern in ignored_patterns:
        print(f" - {pattern}")

    secret_patterns = [
        re.compile(r"(?i)(AWS|API|SECRET|TOKEN|PASSWORD|KEY)[\s=:\"]+([A-Za-z0-9-_]+)"),
        re.compile(r"(?i)(passwd|password|pass)[\s=:\"]+([A-Za-z0-9-_]+)"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),  # GitHub Token
        re.compile(r"eyJ[a-zA-Z0-9]{20,}\.[a-zA-Z0-9_-]+"),  # JWT Token
        re.compile(r"ssh-rsa [A-Za-z0-9+/=]+"),  # SSH Key
        re.compile(r"(?i)(db_pass|db_password|db_user|access_key|secret_key)[\s=:\"]+([A-Za-z0-9-_]+)"),
    ]

    # Run file scanning tasks in parallel
    tasks = [find_secrets_in_file(file_path, secret_patterns) for file_path in files_to_scan]
    all_results = await asyncio.gather(*tasks)

    # Flatten the results
    all_results = [result for results in all_results for result in results]

    if all_results:
        print("\nFound secrets:")
        print_results_table(all_results)

        save_results_json(all_results, root_dir / "secrets.json")
        save_results_csv(all_results, root_dir / "secrets.csv")
        print("\nResults saved to secrets.json and secrets.csv")
    else:
        print("\nNo secrets found.")


if __name__ == "__main__":
    asyncio.run(main())
  
