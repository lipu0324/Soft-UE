#!/usr/bin/env python3
"""Run a real 4 GiB-1 native READ with bounded-state and byte-verification evidence."""
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
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--nscc", action="store_true")
    parser.add_argument("--ack-data", action="store_true", help="Use the fabric branch whose ACK data limit equals Payload MTU")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    binary, output = args.binary.resolve(), args.output.resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip())
    build_info = json.loads(subprocess.check_output([str(binary), "--build-info"], text=True))
    if dirty or build_info != {"source_commit": commit, "source_dirty": False}:
        parser.error("reconfigure and build this binary from clean current HEAD before a boundary experiment")
    requirements = json.loads((root / "DOC/ue11/requirements.json").read_text())
    output.mkdir(parents=True, exist_ok=True)
    command = [str(binary), "--bytes", "4294967295"]
    if args.nscc:
        command.append("--nscc")
    if args.ack_data:
        command.append("--ack-data")
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    returncode, timed_out = None, False
    log_path = output / "streaming.log"
    with log_path.open("w") as log:
        try:
            returncode = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    elapsed = time.perf_counter() - started
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    log_text = log_path.read_text()
    fields = ["bytes", "fragments", "reads", "verified_bytes", "peak_queued", "result_window", "target_credits",
              "source_intervals", "target_intervals", "source_pages", "target_pages", "nscc", "ack_data", "buffer_bytes", "drops"]
    match = re.search("PASS streaming-read " + " ".join(field + r"=(\d+)" for field in fields), log_text)
    observed = dict(zip(fields, map(int, match.groups()))) if match else None
    passed = returncode == 0 and observed is not None
    if observed is not None:
        passed = passed and observed["bytes"] == 4294967295 and observed["verified_bytes"] == 4294967295
        passed = passed and observed["fragments"] == 524288 and observed["reads"] >= 524288
        passed = passed and all(observed[field] <= 8 for field in ["peak_queued", "result_window", "target_credits"])
        passed = passed and all(observed[field] <= 1 for field in ["source_intervals", "target_intervals"])
        passed = passed and all(observed[field] <= 3 for field in ["source_pages", "target_pages"])
        passed = passed and bool(observed["nscc"]) == args.nscc and bool(observed["ack_data"]) == args.ack_data
        passed = passed and observed["buffer_bytes"] == 1048576 and observed["drops"] == 0
    report = {
        "schema_version": 1, "experiment": "streamed-native-read-boundary", "passed": bool(passed),
        "source_commit": commit, "source_dirty": dirty, "embedded_build_info": build_info,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "specification_sha256": requirements["specification_sha256"],
        "softue_baseline": requirements["softue_baseline"], "command": command,
        "returncode": returncode, "timed_out": timed_out, "observed": observed,
        "carrier": "data-acknowledgment" if args.ack_data else "same-pdc-return-request",
        "congestion_control": "NSCC" if args.nscc else "disabled",
        "nscc_return_counter_wrap_required": args.nscc and not args.ack_data,
        "fragment_count_note": "Fragments count actual unique local placements; reads also count any READ re-execution. Every placed byte is checked against the sparse marker pattern.",
        "executor_measurements": {
            "wall_seconds": elapsed, "child_user_seconds": usage_after.ru_utime - usage_before.ru_utime,
            "child_system_seconds": usage_after.ru_stime - usage_before.ru_stime,
            "children_peak_rss_kib": usage_after.ru_maxrss,
            "note": "Linux executor measurements, not target hardware throughput or memory requirements.",
        },
        "profile_conformance": False,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": bool(passed), "observed": observed, "report": str(output / "report.json")}))
    if not passed:
        print(log_text[-6000:])
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
