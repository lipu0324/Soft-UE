#!/usr/bin/env python3
"""Exercise the loaded provider through two public-API-only libfabric apps."""
import argparse
import os
from pathlib import Path
import subprocess
import json
import sys
import tempfile
from test_reference_interop import ready


def exchange(binary, provider_directory):
    environment = dict(os.environ, FI_PROVIDER="softue",
                       FI_PROVIDER_PATH=str(Path(provider_directory).resolve()))
    peers = []
    transcripts = {}
    failed = True
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
        for index, peer in enumerate(peers):
            output, errors = peer.communicate(timeout=15)
            transcripts[index] = (output, errors)
            if peer.returncode or "PASS libfabric" not in output:
                # Keep the first CHECK/error as well as the sanitizer tail.
                # A large leak report must not hide why the application exited.
                stderr_excerpt = errors if len(errors) <= 18000 else errors[:4000] + "\n...\n" + errors[-14000:]
                failures.append(f"exit={peer.returncode}\n{output[-10000:]}\n{stderr_excerpt}")
            else:
                print(output.strip())
        if failures:
            raise RuntimeError("\n".join(failures))
        failed = False
    finally:
        for index, peer in enumerate(peers):
            if peer.poll() is None:
                peer.kill()
            if index not in transcripts:
                transcripts[index] = peer.communicate()
        if failed:
            directory = Path(__file__).resolve().parents[1] / "build"
            directory.mkdir(exist_ok=True)
            artifact = Path(tempfile.mkdtemp(prefix="libfabric-process-failure-", dir=directory))
            for index, (output, errors) in transcripts.items():
                role = "server" if index == 0 else "client"
                (artifact / f"{role}.stdout.log").write_text(output)
                (artifact / f"{role}.stderr.log").write_text(errors)
            (artifact / "processes.json").write_text(json.dumps({"binary": str(binary), "provider_directory": str(provider_directory),
                "returncodes": [peer.returncode for peer in peers]}, indent=2) + "\n")
            print(f"Complete libfabric process evidence retained at {artifact}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--provider-directory", required=True)
    arguments = parser.parse_args()
    exchange(arguments.binary, arguments.provider_directory)
