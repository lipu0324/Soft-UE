#!/usr/bin/env python3
"""Validate a YAML experiment and run the deterministic Soft-UE protocol core."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML is required: install python3-yaml or PyYAML")


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def mapping(value, allowed, location):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError(f"invalid or unknown fields in {location}")
    return value


def integer(value, lower, upper, name):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def identifiers(value, name, maximum, minimum=1):
    if not isinstance(value, list) or any(type(x) is not int for x in value):
        raise ValueError(f"{name} must be a list of integers")
    result = [integer(x, minimum, maximum, name) for x in value]
    if len(set(result)) != len(result):
        raise ValueError(f"duplicate {name}")
    return result


def validate(config):
    mapping(config, {"version", "profile", "seed", "duration_ns", "event_budget", "memory_bytes", "wire",
                     "hosts", "switches", "jobs", "links", "operations", "nscc", "trimming", "payload_mtu", "link_events", "rto_ns"}, "scenario")
    if config.get("version") != 1 or type(config.get("version")) is not int:
        raise ValueError("scenario version must be 1")
    if config.get("profile", "experimental") != "experimental":
        raise ValueError("no complete UE profile is validated yet; use profile: experimental")
    hosts = identifiers(config.get("hosts"), "hosts", 0xffffffff)
    if not 2 <= len(hosts) <= 64:
        raise ValueError("the initial simulator supports 2 to 64 hosts")
    switches = identifiers(config.get("switches", []), "switches", 0xffffffff)
    if set(hosts) & set(switches):
        raise ValueError("host and switch IDs must be disjoint")
    jobs = identifiers(config.get("jobs", [1]), "jobs", 0xffffff, minimum=0)
    if not jobs:
        raise ValueError("at least one JobID is required")
    seed = integer(config.get("seed", 42), 0, 2**64 - 1, "seed")
    duration = integer(config.get("duration_ns", 100_000_000), 1, 2**63 - 1, "duration_ns")
    budget = integer(config.get("event_budget", 1_000_000), 1, 100_000_000, "event_budget")
    memory = integer(config.get("memory_bytes", 65536), 1, 2**64 - 1, "memory_bytes")
    payload_mtu = integer(config.get("payload_mtu", 1024), 1, 8192, "payload_mtu")
    rto_ns = integer(config.get("rto_ns", 1_000_000), 0, 8_000_000_000, "rto_ns")
    trimming = config.get("trimming", False)
    if type(trimming) is not bool:
        raise ValueError("trimming must be boolean")
    wire = mapping(config.get("wire", {}), {"ipv6", "udp", "crc"}, "wire")
    flags = [wire.get("ipv6", False), wire.get("udp", False), wire.get("crc", True)]
    if any(type(flag) is not bool for flag in flags):
        raise ValueError("wire ipv6/udp/crc fields must be booleans")
    records = ["softue-scenario-v2", f"seed {seed}", f"duration {duration}", f"budget {budget}",
               f"memory {memory}", f"payload_mtu {payload_mtu}", f"rto {rto_ns}", f"trimming {int(trimming)}",
               "wire " + " ".join(str(int(x)) for x in flags)]
    nscc = mapping(config.get("nscc", {}), {"enabled", "base_rtt_ns", "sender_bytes_per_second",
                   "receiver_bytes_per_second", "nominal_mtu", "initial_window_bytes"}, "nscc")
    nscc_enabled = nscc.get("enabled", False)
    if type(nscc_enabled) is not bool:
        raise ValueError("nscc.enabled must be boolean")
    nominal_mtu = integer(nscc.get("nominal_mtu", payload_mtu + 100 + 4 * flags[1] + 4 * flags[2]),
                          1, 65535, "nscc.nominal_mtu")
    nscc_values = [integer(nscc.get("base_rtt_ns", 12000), 1, 2**61 - 1, "nscc.base_rtt_ns"),
                   integer(nscc.get("sender_bytes_per_second", 12_500_000_000), 1, 2**63 - 1, "nscc.sender_bytes_per_second"),
                   integer(nscc.get("receiver_bytes_per_second", 12_500_000_000), 1, 2**63 - 1, "nscc.receiver_bytes_per_second"),
                   nominal_mtu, integer(nscc.get("initial_window_bytes", 0), 0, 2**62 - 1, "nscc.initial_window_bytes")]
    if nscc_values[-1] and nscc_values[-1] < nominal_mtu:
        raise ValueError("initial NSCC window must admit at least one nominal MTU")
    if nscc_values[0] * nscc_values[1] > ((2**63 - 1) // 3) * 10**9:
        raise ValueError("NSCC sender bandwidth-delay product exceeds the model's signed accounting range")
    records.append("nscc " + " ".join(map(str, [int(nscc_enabled), *nscc_values])))
    records.extend(f"host {x}" for x in sorted(hosts))
    records.extend(f"switch {x}" for x in sorted(switches))
    records.extend(f"job {x}" for x in sorted(jobs))
    nodes = set(hosts + switches)
    edges = set()
    links = config.get("links")
    if not isinstance(links, list) or not links:
        raise ValueError("links must be a nonempty list")
    for item in links:
        mapping(item, {"from", "to", "bidirectional", "rate_bps", "delay_ns", "fec_delay_ns", "mtu",
                       "buffer_bytes", "drop_ppm", "extra_delay_ns", "ecn_threshold_bytes", "traffic_class_weights",
                       "scheduling_quantum_bytes", "trimming"}, "link")
        a = integer(item.get("from"), 1, 0xffffffff, "link.from")
        b = integer(item.get("to"), 1, 0xffffffff, "link.to")
        if a not in nodes or b not in nodes or a == b:
            raise ValueError("link endpoints must be distinct declared nodes")
        bidirectional = item.get("bidirectional", True)
        if type(bidirectional) is not bool:
            raise ValueError("bidirectional must be boolean")
        mtu = integer(item.get("mtu", 9216), 128, 65535, "mtu")
        values = [integer(item.get("rate_bps", 100_000_000_000), 1, 2**64 - 1, "rate_bps"),
                  integer(item.get("delay_ns", 1000), 0, 2**63 - 1, "delay_ns"),
                  integer(item.get("fec_delay_ns", 0), 0, 2**63 - 1, "fec_delay_ns"), mtu,
                  integer(item.get("buffer_bytes", 65536), mtu, 2**63 - 1, "buffer_bytes"),
                  integer(item.get("drop_ppm", 0), 0, 1_000_000, "drop_ppm"),
                  integer(item.get("extra_delay_ns", 0), 0, 2**63 - 1, "extra_delay_ns")]
        thresholds = item.get("ecn_threshold_bytes", [None] * 8)
        weights = item.get("traffic_class_weights", [1] * 8)
        if not isinstance(thresholds, list) or len(thresholds) != 8 or not isinstance(weights, list) or len(weights) != 8:
            raise ValueError("ECN thresholds and traffic-class weights require exactly eight entries")
        thresholds = [2**64 - 1 if value is None else integer(value, 0, 2**63 - 1, "ECN threshold") for value in thresholds]
        weights = [integer(value, 1, 65535, "traffic-class weight") for value in weights]
        quantum = integer(item.get("scheduling_quantum_bytes", 256), 1, 2**32 - 1, "scheduling_quantum_bytes")
        link_trimming = item.get("trimming", trimming)
        if type(link_trimming) is not bool or (link_trimming and not trimming):
            raise ValueError("link trimming requires the common endpoint trimming configuration")
        for source, target in [(a, b), (b, a)] if bidirectional else [(a, b)]:
            if (source, target) in edges:
                raise ValueError("duplicate directed link")
            edges.add((source, target))
            records.append("link " + " ".join(map(str, [source, target, *values])))
            records.append("queue " + " ".join(map(str, [source, target, quantum, int(link_trimming), *weights, *thresholds])))
    events = config.get("link_events", [])
    if not isinstance(events, list) or len(events) > 4096:
        raise ValueError("link_events must be a list with at most 4096 entries")
    event_keys = set()
    for event in events:
        mapping(event, {"at_ns", "from", "to", "up"}, "link event")
        at = integer(event.get("at_ns"), 0, duration - 1, "link event time")
        source = integer(event.get("from"), 1, 0xffffffff, "link event source")
        target = integer(event.get("to"), 1, 0xffffffff, "link event target")
        up = event.get("up")
        event_key = (at, source, target)
        if type(up) is not bool or (source, target) not in edges or event_key in event_keys:
            raise ValueError("link event needs an existing directed link, boolean up and a unique time/link pair")
        event_keys.add(event_key)
        records.append("link_event " + " ".join(map(str, [at, source, target, int(up)])))
    operations = config.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 4096:
        raise ValueError("operations must contain 1 to 4096 entries")
    contexts, send_targets = set(), set()
    payload_budget = 64 * 1024 * 1024
    ranges = {}
    for number, item in enumerate(operations, 1):
        mapping(item, {"type", "source", "target", "job", "bytes", "offset", "context", "at_ns", "expect", "delivery_mode"}, "operation")
        kind = {"noop": 0, "write": 1, "send": 5}.get(item.get("type"))
        if kind is None:
            raise ValueError("initial runner operations are noop, write and send")
        source = integer(item.get("source"), 1, 0xffffffff, "source")
        target = integer(item.get("target"), 1, 0xffffffff, "target")
        job = integer(item.get("job", 1), 0, 0xffffff, "job")
        if source not in hosts or target not in hosts or source == target or job not in jobs:
            raise ValueError("operation requires distinct declared hosts and a declared JobID")
        count = integer(item.get("bytes", 0 if kind == 0 else 257), 0, 16 * 1024 * 1024, "bytes")
        payload_budget -= count
        if payload_budget < 0:
            raise ValueError("initial runner payload budget is 64 MiB per scenario")
        offset = integer(item.get("offset", 0), 0, 2**64 - 1, "offset")
        if (kind == 0 and count) or offset > memory or count > memory - offset:
            raise ValueError("operation exceeds registered memory or NO_OP has payload")
        context = integer(item.get("context", number), 1, 2**64 - 1, "context")
        if context in contexts:
            raise ValueError("operation contexts must be unique")
        contexts.add(context)
        at = integer(item.get("at_ns", 0), 0, duration - 1, "at_ns")
        # Native CompletionStatus includes local datagram outcomes before the
        # reliable-operation errors; these are API values, not SES wire codes.
        expected = {"success": 0, "remote_error": 5, "timeout": 6}.get(item.get("expect", "success"))
        if expected is None:
            raise ValueError("expect must be success, remote_error or timeout")
        mode = {"rud": 0, "rod": 1}.get(item.get("delivery_mode", "rod"))
        if mode is None:
            raise ValueError("delivery_mode must be rud or rod")
        # Standard SES header(44), RUD/ROD PDS request(12), entropy(4)/UDP(8),
        # optional CRC(4), plus the NSCC nominal overhead(40), §3.6.12.2.
        fragment_bytes = min(count, payload_mtu)
        nominal_bytes = fragment_bytes + 100 + 4 * flags[1] + 4 * flags[2]
        if nscc_enabled and nominal_bytes > nominal_mtu:
            raise ValueError("NSCC nominal MTU cannot hold an operation's largest fragment")
        frame_bytes = nominal_bytes - 40 + (40 if flags[0] else 20) + 14
        # This runner uses a common frame size across the topology. Native API
        # fixtures cover heterogeneous-MTU/path-specific admission experiments.
        if any(link.get("mtu", 9216) < max(frame_bytes, 128) for link in links):
            raise ValueError("every scenario link MTU must hold the largest configured frame")
        if kind != 0 and count:
            for begin, end in ranges.setdefault((target, job), []):
                if offset < end and begin < offset + count:
                    raise ValueError("runner verification requires disjoint target ranges; use the native API for overlap tests")
            ranges[target, job].append((offset, offset + count))
        if kind == 5:
            if (target, job) in send_targets:
                raise ValueError("runner supports one posted SEND per target/job; use the native API for receive-queue tests")
            send_targets.add((target, job))
        records.append("flow " + " ".join(map(str, [kind, source, target, job, count, offset, context, at, expected, mode])))
    return "\n".join(records) + "\n"


def provenance(root):
    command = lambda *args: subprocess.check_output(["git", "-C", str(root), *args])
    paths = command("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
    digest = hashlib.sha256()
    for raw in sorted(set(paths)):
        if raw:
            path = root / raw.decode()
            if path.is_file():
                digest.update(raw + b"\0" + path.read_bytes())
    return {"baseline_commit": command("rev-parse", "HEAD").decode().strip(),
            "working_tree_dirty": bool(command("status", "--porcelain")),
            "source_sha256": digest.hexdigest(),
            "reference_commit": "5b4e0491329b8e28764bca6847e2f6a0eaa84b9b",
            "specification": "UE 1.1 (2026-10-12)",
            "specification_sha256": "4c8436ec7daa627ad6cce0680bea66cfac496dfe4e217631064e68acafe04531"}


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--output", type=Path, default=root / "build" / "simulation")
    parser.add_argument("--binary", type=Path, default=root / "build" / "softue_sim")
    args = parser.parse_args()
    try:
        original = args.scenario.read_text()
        config = yaml.load(original, Loader=UniqueLoader)
        normalized = validate(config)
        binary = args.binary.resolve()
        if not binary.is_file():
            raise ValueError("simulation binary missing; run make simulation first")
        output = args.output.resolve()
        if output == root or root.is_relative_to(output):
            raise ValueError("output must not be the source root or its parent")
        output.mkdir(parents=True, exist_ok=True)
        (output / "scenario.yaml").write_text(original)
        config_path = output / "scenario.config"
        config_path.write_text(normalized)
        metadata = provenance(root)
        metadata["scenario_sha256"] = hashlib.sha256(normalized.encode()).hexdigest()
        metadata["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        metadata["capture_boundaries"] = {"packets.pcap": "FEP send submission before NIC queuing",
                                          "link-packets.pcap": "directed-link first-bit departure after trim, ECN and ACK service stamp",
                                          "link-packets.jsonl": "one-based PCAP record index and directed link"}
        metadata["status_codes"] = {"0": "success", "1": "local_success", "2": "local_error", "3": "unsupported",
                                    "4": "invalid_request", "5": "remote_error", "6": "timeout", "7": "cancelled",
                                    "8": "resource_exhausted", "9": "truncated"}
        metadata["run_complete"] = False
        for artifact in ["result.json", "trace.jsonl", "packets.pcap", "link-packets.pcap", "link-packets.jsonl", "protocol.log"]:
            (output / artifact).unlink(missing_ok=True)
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        result = subprocess.run([str(binary), str(config_path), str(output)], cwd=output, timeout=120)
        metadata["run_complete"] = result.returncode == 0
        metadata["exit_code"] = result.returncode
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        if result.returncode < 0:
            print(f"simulation terminated by signal {-result.returncode}; artifacts: {output}", file=sys.stderr)
        print(f"{'PASS' if result.returncode == 0 else 'FAIL'}: {output}")
        return 0 if result.returncode == 0 else 1
    except (TypeError, ValueError, OSError, yaml.YAMLError, subprocess.SubprocessError) as error:
        print(f"scenario rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
