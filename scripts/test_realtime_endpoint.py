#!/usr/bin/env python3
"""Two real processes exchange standard UE frames over an unprivileged tunnel."""
import argparse
import selectors
import subprocess
import time


def ready(process):
    deadline = time.monotonic() + 10
    with selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline-time.monotonic())):
                break
            line = process.stderr.readline()
            if line.startswith("READY "):
                _, port, key = line.split()
                return port, key
            if not line:
                break
    raise RuntimeError(f"peer did not become ready (exit={process.poll()})")


def exchange(binary, mode):
    peers = []
    try:
        for role in ("server", "client"):
            peers.append(subprocess.Popen([binary, role, mode], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True))
        identities = [ready(peer) for peer in peers]
        for index, peer in enumerate(peers):
            peer.stdin.write(" ".join(identities[1-index])+"\n")
            peer.stdin.flush()
        failures = []
        for peer in peers:
            output, errors = peer.communicate(timeout=12)
            if peer.returncode or "PASS " not in output:
                failures.append(f"{mode}: exit={peer.returncode}\n{output}\n{errors}")
            else:
                print(output.strip())
        if failures:
            raise RuntimeError("\n".join(failures))
    finally:
        for peer in peers:
            if peer.poll() is None:
                peer.kill()
                peer.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    for encapsulation in ("ipv4-native", "ipv6-udp"):
        exchange(args.binary, encapsulation)
