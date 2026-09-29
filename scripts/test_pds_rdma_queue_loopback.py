#!/usr/bin/env python3
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "build" / "pds_rdma_queue_loopback_test"

def main():
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    server_log = ROOT / "build" / "pds_rdma_queue_server.log"
    client_log = ROOT / "build" / "pds_rdma_queue_client.log"
    with server_log.open("w") as so, client_log.open("w") as co:
        server = subprocess.Popen([str(BINARY), "--server", "--port", str(port)], cwd=ROOT, stdout=so, stderr=subprocess.STDOUT)
        try:
            time.sleep(0.25)
            client = subprocess.run([str(BINARY), "--client", "--peer", "127.0.0.1", "--port", str(port)], cwd=ROOT, stdout=co, stderr=subprocess.STDOUT, timeout=35)
            code = server.wait(timeout=10)
            if client.returncode or code:
                raise RuntimeError(f"server={code}, client={client.returncode}\nserver:\n{server_log.read_text()}\nclient:\n{client_log.read_text()}")
        finally:
            if server.poll() is None:
                server.terminate(); server.wait(timeout=3)
    print("PASS: PDS queue TX/RX over local mlx5_1 RDMA")

if __name__ == "__main__":
    main()
