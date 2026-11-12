#!/usr/bin/env python3
"""Exercise the loaded provider through two public-API-only libfabric apps."""
import argparse
import os
from pathlib import Path
import subprocess
from test_reference_interop import ready


def exchange(binary, provider_directory):
    environment = dict(os.environ, FI_PROVIDER="softue",
                       FI_PROVIDER_PATH=str(Path(provider_directory).resolve()))
    peers = []
    try:
        for role in ("server", "client"):
            peers.append(subprocess.Popen([binary, role], env=environment,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True))
        identities = [ready(peer) for peer in peers]
        for index, peer in enumerate(peers):
            peer.stdin.write(" ".join(identities[1-index])+"\n")
            peer.stdin.flush()
        failures = []
        for peer in peers:
            output, errors = peer.communicate(timeout=15)
            if peer.returncode or "PASS libfabric" not in output:
                failures.append(f"exit={peer.returncode}\n{output[-10000:]}\n{errors[-15000:]}")
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
    parser.add_argument("--provider-directory", required=True)
    arguments = parser.parse_args()
    exchange(arguments.binary, arguments.provider_directory)
