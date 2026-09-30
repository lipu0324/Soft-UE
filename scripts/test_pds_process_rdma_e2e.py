#!/usr/bin/env python3
"""Run the formal PDS process loop over a local RDMA RC connection."""

from pathlib import Path
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "build" / "pds_process_rdma_e2e_test"


def main() -> None:
    device = sys.argv[1] if len(sys.argv) > 1 else "mlx5_1"
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]

    server_log = ROOT / "build" / "pds_process_rdma_server.log"
    client_log = ROOT / "build" / "pds_process_rdma_client.log"
    with server_log.open("w") as server_out, client_log.open("w") as client_out:
        server = subprocess.Popen(
            [str(BINARY), "--server", "--port", str(port), "--device", device],
            cwd=ROOT,
            stdout=server_out,
            stderr=subprocess.STDOUT,
        )
        try:
            time.sleep(0.25)
            client = subprocess.run(
                [
                    str(BINARY), "--client", "--peer", "127.0.0.1",
                    "--port", str(port), "--device", device,
                ],
                cwd=ROOT,
                stdout=client_out,
                stderr=subprocess.STDOUT,
                timeout=45,
                check=False,
            )
            server_code = server.wait(timeout=15)
            if client.returncode or server_code:
                raise RuntimeError(
                    f"server={server_code}, client={client.returncode}\n"
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
    print("PASS: formal PDS process loop over local RDMA")


if __name__ == "__main__":
    main()
