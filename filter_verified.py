#!/usr/bin/env python3
"""
Filter verified vulnerabilities from explore.json and separate them by type.

Reads explore.json (NDJSON format from LeakIX), keeps only records where
event_type is "leak" (verified vulnerabilities), and writes:
  - verified.json: all verified vulnerabilities combined
  - One file per vulnerability type (event_source), e.g. PhpInfoHttpPlugin.json
"""

import json
import os
import sys


def main():
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "explore.json")
    output_dir = os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found", file=sys.stderr)
        sys.exit(1)

    # Group verified vulnerabilities by event_source
    verified_by_type = {}
    total_records = 0
    verified_count = 0

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_records += 1
            record = json.loads(line)

            if record.get("event_type") != "leak":
                continue

            verified_count += 1
            source = record.get("event_source", "unknown")
            if source not in verified_by_type:
                verified_by_type[source] = []
            verified_by_type[source].append(record)

    # Write combined verified.json
    verified_path = os.path.join(output_dir, "verified.json")
    with open(verified_path, "w", encoding="utf-8") as f:
        for source in sorted(verified_by_type.keys()):
            for record in verified_by_type[source]:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"Written {verified_count} verified vulnerabilities to verified.json")

    # Write separate files per vulnerability type
    for source, records in sorted(verified_by_type.items()):
        filename = f"{source}.json"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"Written {len(records)} records to {filename}")

    # Summary
    print(f"\nSummary:")
    print(f"  Total records in explore.json: {total_records}")
    print(f"  Verified vulnerabilities: {verified_count}")
    print(f"  Discarded (non-verified): {total_records - verified_count}")
    print(f"  Vulnerability types: {len(verified_by_type)}")
    for source in sorted(verified_by_type.keys()):
        print(f"    - {source}: {len(verified_by_type[source])} records")


if __name__ == "__main__":
    main()
