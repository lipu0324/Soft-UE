#!/usr/bin/env python3
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "build" / "pds_udp_queue_loopback_test"


def main():
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]

    server_log = ROOT / "build" / "pds_udp_queue_server.log"
    client_log = ROOT / "build" / "pds_udp_queue_client.log"
    with server_log.open("w") as server_out, client_log.open("w") as client_out:
        server = subprocess.Popen(
            [str(BINARY), "--server", "--port", str(port)],
            cwd=ROOT,
            stdout=server_out,
            stderr=subprocess.STDOUT,
        )
        try:
            time.sleep(0.1)
            client = subprocess.run(
                [str(BINARY), "--client", "--peer", "127.0.0.1", "--port", str(port)],
                cwd=ROOT,
                stdout=client_out,
                stderr=subprocess.STDOUT,
                timeout=10,
            )
            server_code = server.wait(timeout=5)
            if client.returncode or server_code:
                raise RuntimeError(
                    f"server={server_code}, client={client.returncode}\n"
                    f"server:\n{server_log.read_text()}\n"
                    f"client:\n{client_log.read_text()}"
                )
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=3)
    print("PASS: UDP prequeued outbound peer learning")


if __name__ == "__main__":
    main()
