#!/usr/bin/env python3
"""Scenario validation, replay, PCAP integrity and a 64-host real-PDC regression."""
import argparse
import copy
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


def read_pcap(path):
    """Independent record parser; do not invoke the production wire codec."""
    capture = path.read_bytes()
    check(capture[:4] == b"\x4d\x3c\xb2\xa1", "invalid nanosecond PCAP magic")
    check(struct.unpack_from("<I", capture, 20)[0] == 1, "PCAP is not Ethernet")
    offset, records = 24, []
    while offset < len(capture):
        seconds, fraction, captured, actual = struct.unpack_from("<IIII", capture, offset)
        frame = capture[offset + 16:offset + 16 + captured]
        check(fraction < 10**9 and captured == actual and len(frame) == captured, "invalid PCAP record")
        records.append((seconds * 10**9 + fraction, frame))
        offset += 16 + captured
    check(offset == len(capture), "truncated PCAP")
    return records


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
               dict(base, profile="AI_BASE"), dict(base, unknown=True), dict(base, seed=True),
               dict(base, nscc={"enabled": 1}), dict(base, nscc={"enabled": True, "nominal_mtu": 100}),
               dict(base, trimming="true"), dict(base, payload_mtu=0),
               dict(base, rto_ns=True), dict(base, rto_ns=8_000_000_001),
               dict(base, max_packet_retries=True), dict(base, max_packet_retries=-1),
               dict(base, max_packet_retries=16), dict(base, max_packet_retries=1.5),
               dict(base, nack_delays_ns=[0, 1]), dict(base, nack_delays_ns=[0, 0, 0, True]),
               dict(base, nack_delays_ns=[0, 0, 0, 8_000_000_001]),
               dict(base, link_events=[{"at_ns": 0, "from": 1, "to": 3, "up": False}]),
               dict(base, link_events=[{"at_ns": 0, "from": 1, "to": 2, "up": "false"}])]
    for settings in [{"ecn_threshold_bytes": [0] * 7}, {"traffic_class_weights": [0] * 8},
                     {"trimming": True}, {"scheduling_quantum_bytes": False}, {"mtu": 128}]:
        bad_link = copy.deepcopy(base)
        bad_link["links"][0].update(settings)
        invalid.append(bad_link)
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

        first, first_result = run(base, "first")
        check(not first_result["fairness"]["eligible"] and first_result["fairness"]["jain_index"] is None,
              "a single flow must not be labeled a fairness measurement")
        second, _ = run(base, "second")
        for name in ["trace.jsonl", "result.json", "packets.pcap", "link-packets.pcap", "link-packets.jsonl"]:
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
        link_frames = read_pcap(first / "link-packets.pcap")
        link_index = [json.loads(line) for line in (first / "link-packets.jsonl").read_text().splitlines()]
        check(len(link_frames) == len(link_index) > 0, "per-hop index does not cover every wire frame")
        for ordinal, ((time, frame), record) in enumerate(zip(link_frames, link_index), 1):
            check(record["record"] == ordinal and record["time_ns"] == time and record["bytes"] == len(frame),
                  "per-hop PCAP record cannot be joined to its link")
        metadata = json.loads((first / "metadata.json").read_text())
        check(len(metadata["binary_sha256"]) == 64 and "link-packets.pcap" in metadata["capture_boundaries"],
              "missing binary/capture provenance")

        incast = {"version": 1, "hosts": [1, 2, 3, 4], "switches": [10], "duration_ns": 50_000_000,
                  "nscc": {"enabled": True, "receiver_bytes_per_second": 125_000_000},
                  "links": [{"from": host, "to": 10} for host in [1, 2, 3]] +
                           [{"from": 10, "to": 4, "rate_bps": 1_000_000_000,
                             "ecn_threshold_bytes": [0] + [None] * 7}],
                  "operations": [{"type": "write", "delivery_mode": "rud", "source": source,
                                  "target": 4, "bytes": 8192, "offset": (source - 1) * 8192} for source in [1, 2, 3]]}
        incast_output, incast_result = run(incast, "nscc-incast")
        incast_replay, _ = run(incast, "nscc-incast-replay")
        for name in ["trace.jsonl", "result.json", "packets.pcap", "link-packets.pcap", "link-packets.jsonl"]:
            check((incast_output / name).read_bytes() == (incast_replay / name).read_bytes(), f"non-deterministic NSCC {name}")
        check(incast_result["nscc_enabled"] and incast_result["completed_bytes"] == 3 * 8192,
              "NSCC incast did not traverse memory-verified operations")
        check(incast_result["fairness"]["eligible"] and 0 < incast_result["fairness"]["jain_index"] <= 1.00000001,
              "equal-workload flow goodput fairness is missing or invalid")
        check(all(operation["flow_completion_ns"] > 0 for operation in incast_result["operations"]),
              "missing actual application completion timing")
        check(sum(link["ecn_marked"] for link in incast_result["links"]) > 0, "configured ECN was not applied")
        check(any(frame[15] & 3 == 3 for _, frame in read_pcap(incast_output / "link-packets.pcap")),
              "actual captured IPv4 frames do not contain the reported CE marks")
        check(all(len(link["traffic_classes"]) == 8 for link in incast_result["links"]), "missing per-TC occupancy")

        trimmed = copy.deepcopy(incast)
        trimmed["trimming"] = True
        trimmed["nack_delays_ns"] = [10000, 2000000, 1000000, 0]
        trimmed["links"][-1].update(mtu=1500, buffer_bytes=1500)
        trim_output, trim_result = run(trimmed, "nscc-trim-incast")
        check(sum(link["trimmed"] for link in trim_result["links"]) > 0, "configured congestion never trimmed")
        trim_capture = read_pcap(trim_output / "link-packets.pcap")
        trim_frames = [frame for _, frame in trim_capture
                       if frame[15] >> 2 in [8, 16]]
        original_prefixes = {frame[34:58] for _, frame in trim_capture if frame[15] >> 2 == 0 and len(frame) > 58}
        check(trim_frames and all(len(frame) == 58 and int.from_bytes(frame[16:18], "big") == 44
                                  and frame[34:] in original_prefixes for frame in trim_frames),
              "per-hop PCAP must contain the real 24-byte retained IP payload and repaired IP length")
        check(trim_result["source_data_retransmissions"] > 0, "trim recovery bypassed original PDS retries")
        run(dict(trimmed, wire={"ipv6": True, "udp": True}), "nscc-trim-ipv6-udp")

        outage = copy.deepcopy(base)
        outage["nscc"] = {"enabled": True}
        outage["rto_ns"] = 50000
        outage["max_packet_retries"] = 15
        outage["link_events"] = [{"at_ns": 0, "from": 1, "to": 2, "up": False},
                                 {"at_ns": 40000, "from": 1, "to": 2, "up": True}]
        outage_output, outage_result = run(outage, "temporary-no-route")
        check(outage_result["operations"][0]["flow_completion_ns"] < 100000,
              "configured nanosecond RTO was rounded up to a millisecond")
        outage_events = [json.loads(line)["event"] for line in (outage_output / "trace.jsonl").read_text().splitlines()]
        check("nic_rejected" in outage_events and "link_down" in outage_events and "link_up" in outage_events,
              "timed link events did not exercise local rejection and recovery")

        multipath = copy.deepcopy(base)
        multipath["switches"] = [10, 20]
        multipath["nscc"] = {"enabled": True}
        multipath["links"] = [{"from": 1, "to": switch} for switch in [10, 20]] + \
                             [{"from": switch, "to": 2, "extra_delay_ns": 0 if switch == 10 else 5000} for switch in [10, 20]]
        multipath["operations"][0].update(bytes=32768, delivery_mode="rud")
        paths_output, _ = run(multipath, "asymmetric-paths")
        first_hops = {json.loads(line)["to"] for line in (paths_output / "link-packets.jsonl").read_text().splitlines()
                      if json.loads(line)["from"] == 1}
        check(first_hops == {10, 20}, "RUD scenario did not actually spray both unequal-delay routes")

        leaf = yaml.safe_load((root / "examples" / "simulation" / "leaf-spine.yaml").read_text())
        run(leaf, "ipv6-udp")
        job_zero = dict(base, jobs=[0], operations=[dict(operation, job=0) for operation in base["operations"]])
        run(job_zero, "job-zero")
        lost = {"version": 1, "hosts": [1, 2], "duration_ns": 100_000_000,
                "links": [{"from": 1, "to": 2, "drop_ppm": 1_000_000}],
                "operations": [{"type": "write", "source": 1, "target": 2, "bytes": 16, "expect": "timeout"}]}
        lost_output, lost_result = run(lost, "permanent-loss-status")
        metadata = json.loads((lost_output / "metadata.json").read_text())
        check(lost_result["operations"][0]["status"] == 6 and metadata["status_codes"]["6"] == "timeout",
              "runner must label the actual native timeout, not an obsolete enum position")
        for limit in [0, 1]:
            _, limited_result = run(dict(lost, max_packet_retries=limit), f"loss-retry-limit-{limit}")
            check(limited_result["source_data_attempts"] == limit + 1 and
                  limited_result["source_data_retransmissions"] == limit,
                  "configured retry budget must control actual MAC departures")
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
    print("PASS: YAML rejection, NSCC/CE/trim replay, per-hop PCAP, timed outage, unequal ECMP and 64 hosts")


if __name__ == "__main__":
    main()
