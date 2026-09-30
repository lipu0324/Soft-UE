#!/usr/bin/env python3
"""Run two processes over the local RNIC and verify complete binary messages."""

from pathlib import Path
import sys
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "build" / "rdma_message_test"


def main() -> None:
    udp = "--udp" in sys.argv[1:]
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]

    transport = "udp" if udp else "rdma"
    server_log = ROOT / "build" / f"{transport}_server.log"
    client_log = ROOT / "build" / f"{transport}_client.log"
    mode_args = ["--udp"] if udp else []
    with server_log.open("w") as server_out, client_log.open("w") as client_out:
        server = subprocess.Popen(
            [str(BINARY), "--server", "--port", str(port), *mode_args],
            cwd=ROOT,
            stdout=server_out,
            stderr=subprocess.STDOUT,
        )
        try:
            time.sleep(0.25)
            client = subprocess.run(
                [str(BINARY), "--client", "--peer", "127.0.0.1", "--port", str(port), *mode_args],
                cwd=ROOT,
                stdout=client_out,
                stderr=subprocess.STDOUT,
                timeout=55,
                check=False,
            )
            server_code = server.wait(timeout=10)
            if client.returncode or server_code:
                raise RuntimeError(
                    f"{transport} test failed: server={server_code}, client={client.returncode}\n"
                    f"server log:\n{server_log.read_text()}\n"
                    f"client log:\n{client_log.read_text()}"
                )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    print(f"PASS: two-process {transport} binary messages")


if __name__ == "__main__":
    main()
