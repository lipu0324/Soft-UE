#!/usr/bin/env python3
"""Scenario validation, replay, PCAP integrity and a 64-host real-PDC regression."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import yaml


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=root / "build" / "softue_sim")
    args = parser.parse_args()
    module_spec = importlib.util.spec_from_file_location("runner", root / "scripts" / "run_simulation.py")
    runner = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(runner)
    base = yaml.safe_load((root / "examples" / "simulation" / "two-host.yaml").read_text())
    invalid = [dict(base, hosts=[1]), dict(base, hosts=list(range(1, 66))),
               dict(base, profile="AI_BASE"), dict(base, unknown=True), dict(base, seed=True)]
    for config in invalid:
        try:
            runner.validate(config)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid configuration was accepted")
    try:
        yaml.load("version: 1\nversion: 2\n", Loader=runner.UniqueLoader)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate YAML key was accepted")
    (root / "build").mkdir(exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="simulation-test-", dir=root / "build"))
    try:

        def run(config, name):
            scenario = temporary / f"{name}.yaml"
            scenario.write_text(yaml.safe_dump(config))
            output = temporary / name
            subprocess.run(["python3", str(root / "scripts" / "run_simulation.py"), str(scenario),
                            "--binary", str(args.binary.resolve()), "--output", str(output)], check=True, timeout=120)
            result = json.loads((output / "result.json").read_text())
            check(result["passed"] and not result["profile_conformance"], "incorrect conformance/result declaration")
            return output, result

        first, _ = run(base, "first")
        second, _ = run(base, "second")
        for name in ["trace.jsonl", "result.json", "packets.pcap"]:
            check((first / name).read_bytes() == (second / name).read_bytes(), f"non-deterministic {name}")
        pcap = (first / "packets.pcap").read_bytes()
        check(pcap[:4] == b"\x4d\x3c\xb2\xa1", "invalid nanosecond PCAP magic")
        check(struct.unpack_from("<I", pcap, 20)[0] == 1, "PCAP is not Ethernet")
        offset, frames = 24, 0
        while offset < len(pcap):
            seconds, fraction, captured, actual = struct.unpack_from("<IIII", pcap, offset)
            check(fraction < 10**9 and captured == actual, "invalid PCAP record")
            frame = pcap[offset + 16:offset + 16 + captured]
            check(len(frame) == captured and frame[12:14] == b"\x08\x00", "invalid Ethernet capture")
            offset += 16 + captured
            frames += 1
        check(offset == len(pcap) and frames > 0, "missing/truncated capture")

        leaf = yaml.safe_load((root / "examples" / "simulation" / "leaf-spine.yaml").read_text())
        run(leaf, "ipv6-udp")
        large = {"version": 1, "seed": 42, "duration_ns": 100_000_000,
                 "hosts": list(range(1, 65)), "switches": list(range(100, 108)) + [200, 201],
                 "links": [], "operations": []}
        for host in large["hosts"]:
            large["links"].append({"from": host, "to": 100 + (host - 1) // 8})
        for leaf_id in range(100, 108):
            for spine in [200, 201]:
                large["links"].append({"from": leaf_id, "to": spine})
        for source in range(1, 33):
            large["operations"].append({"type": "write", "source": source, "target": source + 32,
                                        "bytes": 257, "context": source})
        _, result = run(large, "64-hosts")
        check(result["host_count"] == 64 and len(result["operations"]) == 32, "incomplete large regression")
        check(all(op["completed"] and op["verified"] for op in result["operations"]), "uncompleted large operation")
    except BaseException:
        print(f"Failure artifacts retained at {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)
    print("PASS: YAML rejection, deterministic replay, Ethernet PCAP, IPv6/UDP and 64 hosts")


if __name__ == "__main__":
    main()
