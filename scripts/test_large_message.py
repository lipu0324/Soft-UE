#!/usr/bin/env python3
"""Run the real 4 GiB−1 WRITE experiment and preserve bounded-state evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import time


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    requirements = json.loads((root / "DOC/ue11/requirements.json").read_text())
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    source_dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip())
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    command = [str(binary), "--bytes", "4294967295"]
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    returncode = None
    timed_out = False
    log_path = output / "streaming.log"
    with log_path.open("w") as log:
        try:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    elapsed = time.perf_counter() - started
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    log_text = log_path.read_text()
    match = re.search(r"PASS streaming bytes=(\d+) fragments=(\d+) peak_queued=(\d+) intervals=(\d+) pages=(\d+) loss=(\d+)", log_text)
    observed = dict(zip(["bytes", "unique_data_fragments", "peak_producer_queue", "receive_intervals", "sparse_pages", "injected_loss"],
                        map(int, match.groups()))) if match else None
    passed = returncode == 0 and observed is not None and observed["bytes"] == 4294967295 and observed["unique_data_fragments"] == 524288
    report = {
        "schema_version": 1, "experiment": "streamed-native-write-boundary", "passed": passed,
        "source_commit": source_commit, "source_dirty": source_dirty,
        "binary_sha256": binary_sha256,
        "specification_sha256": requirements["specification_sha256"],
        "softue_baseline": requirements["softue_baseline"], "command": command,
        "returncode": returncode, "timed_out": timed_out, "observed": observed,
        "fragment_count_note": "Unique fragments count application reads; cached retransmissions are not counted. injected_loss excludes any fabric queue loss.",
        "executor_measurements": {
            "wall_seconds": elapsed,
            "child_user_seconds": usage_after.ru_utime - usage_before.ru_utime,
            "child_system_seconds": usage_after.ru_stime - usage_before.ru_stime,
            "children_peak_rss_kib": usage_after.ru_maxrss,
            "note": "Linux executor measurements; peak is the child-process high-water mark including git setup, not target hardware performance.",
        },
        "profile_conformance": False,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": passed, "observed": observed, "report": str(output / "report.json")}))
    if not passed:
        print(log_text[-6000:])
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
