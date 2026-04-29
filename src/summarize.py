import csv
import json
import os
from pathlib import Path

# reads all CSV reports in artifacts/release/ and prints a summary table

ARTIFACTS_DIR = Path("artifacts/release")

def summarize():
    results = []

    for csv_file in ARTIFACTS_DIR.glob("*.csv"):
        with open(csv_file, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(row)

    if not results:
        print("No scan results found in artifacts/release/")
        return
    
    print(f"\n{'='*70}")
    print(f"{'TLS AUDIT SUMMARY':^70}")
    print(f"{'='*70}")
    print(f"{'Host':<30} {'Protocol':<12} {'Cipher':<20} {'Result'}")
    print(f"{'-'*70}")

    passed = 0
    failed = 0

    for r in results:
        result = "PASSED" if r["passed"] == "True" else "FAILED"
        if result == "PASSED":
            passed += 1
        else:
            failed += 1
        cipher_short = r["cipher"][:18]
        print(f"{r['hostname']:<30} {r['protocol']:<12} {cipher_short:<20} {result}")

    print(f"{'-'*70}")
    print(f"Total scans: {len(results)} | Passed: {passed} | Failed: {failed}")
    print(f"{'='*70}\n")

    # save summary as JSON
    summary = {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "results": results
    }

    summary_path = ARTIFACTS_DIR / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Summary saved to {summary_path}")

if __name__ == "__main__":
    summarize()