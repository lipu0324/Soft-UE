#!/usr/bin/env python3
"""Validate traceability records and reject unsupported conformance claims."""
import argparse
import json
from pathlib import Path
import re
import sys


def audit(root):
    matrix = json.loads((root / "DOC" / "ue11" / "requirements.json").read_text())
    cmake = (root / "CMakeLists.txt").read_text()
    tests = set(re.findall(r"softue_test\((\w+)\s", cmake)) | set(re.findall(r"add_test\(NAME\s+(\w+)", cmake))
    ids = set()
    profiles = {"AI_BASE", "AI_FULL", "HPC", "UNIFIED_LOCAL"}
    counts = {status: 0 for status in ["verified", "partial", "missing", "blocked"]}
    errors = []
    for requirement in matrix["requirements"]:
        identifier = requirement["id"]
        if identifier in ids:
            errors.append(f"duplicate requirement: {identifier}")
        ids.add(identifier)
        if requirement["status"] not in counts:
            errors.append(f"invalid status: {identifier}")
            continue
        counts[requirement["status"]] += 1
        if set(requirement["profiles"]) - profiles:
            errors.append(f"unknown profile: {identifier}")
        if requirement["status"] == "verified" and not requirement["tests"]:
            errors.append(f"verified task has no test: {identifier}")
        for test in requirement["tests"]:
            if test not in tests:
                errors.append(f"unregistered test {test}: {identifier}")
    if set(matrix["profile_claims"]) != profiles:
        errors.append("profile claim set is incomplete")
    for profile, advertised in matrix["profile_claims"].items():
        applicable = [r for r in matrix["requirements"] if profile in r["profiles"]]
        if advertised and (not matrix["inventory_complete"] or not applicable or any(r["status"] != "verified" for r in applicable)):
            errors.append(f"unsubstantiated profile claim: {profile}")
    return {"inventory_complete": matrix["inventory_complete"], "profile_claims": matrix["profile_claims"],
            "status_counts": counts, "errors": errors}


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--claim-profile", choices=["AI_BASE", "AI_FULL", "HPC", "UNIFIED_LOCAL"])
    args = parser.parse_args()
    report = audit(root)
    if args.claim_profile and not report["profile_claims"][args.claim_profile]:
        report["errors"].append(f"{args.claim_profile} has not passed profile acceptance")
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized)
    print(serialized, end="")
    return int(bool(report["errors"]))


if __name__ == "__main__":
    sys.exit(main())
