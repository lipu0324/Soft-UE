#!/usr/bin/env python3
"""Run independent Soft-UE and pinned reference protocol stacks in real processes.

Only NIC I/O is adapted to an unprivileged UDP frame tunnel. Address/key setup
travels through stdin; application data and completions travel through UE frames.
"""
import argparse
import selectors
import subprocess
import time


def ready(process):
    deadline = time.monotonic()+10
    startup = []
    with selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline-time.monotonic())):
                break
            line = process.stderr.readline()
            if line.startswith("READY "):
                return line.split()[1:]
            startup.append(line)
            if not line:
                break
    raise RuntimeError(f"interop peer startup failed (exit={process.poll()}): {''.join(startup)}")


def run(reference, peer):
    processes = []
    try:
        for binary in (reference, peer):
            processes.append(subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True))
        reference_identity, peer_identity = [ready(process) for process in processes]
        for process, values in zip(processes, (peer_identity, reference_identity)):
            process.stdin.write(" ".join(values)+"\n")
            process.stdin.flush()
        failures = []
        for process in processes:
            output, errors = process.communicate(timeout=12)
            if process.returncode or "PASS " not in output:
                failures.append(f"exit={process.returncode}\n{output[-10000:]}\n{errors[-15000:]}")
            else:
                print(output.strip())
        if failures:
            raise RuntimeError("\n".join(failures))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    parser.add_argument("--peer", required=True)
    arguments = parser.parse_args()
    run(arguments.reference, arguments.peer)
