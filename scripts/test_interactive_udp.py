#!/usr/bin/env python3
"""Exercise terminal chat over loopback UDP; no active RDMA device is needed."""

import argparse
from pathlib import Path
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 10


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        return reserve.getsockname()[1]


def wait_ready(process, log):
    # The banner is flushed after UdpChannel has bound its socket. Do not
    # replace this with a startup sleep: the first UDP datagram could be lost.
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited before the client started")
        if "Interactive " in log.read_text(encoding="utf-8"):
            return
        time.sleep(0.01)
    raise RuntimeError("server did not become ready")


def exchange(binary, logs, name, server_flags, client_flags,
             server_input, client_input, at_server, at_client):
    case = logs / name
    case.mkdir(parents=True, exist_ok=True)
    server_log = case / "server.log"
    client_log = case / "client.log"
    server_stdin = case / "server.stdin"
    client_stdin = case / "client.stdin"
    server_stdin.write_text(server_input, encoding="utf-8")
    client_stdin.write_text(client_input, encoding="utf-8")
    port = str(free_port())
    server = client = None
    try:
        with server_stdin.open("rb") as sin, client_stdin.open("rb") as cin, \
                server_log.open("wb") as sout, client_log.open("wb") as cout:
            try:
                common = [str(binary), "--udp", "--interactive", "--port", port]
                server = subprocess.Popen(common + ["--server"] + server_flags,
                                          stdin=sin, stdout=sout, stderr=subprocess.STDOUT)
                wait_ready(server, server_log)
                client = subprocess.Popen(
                    common + ["--client", "--peer", "127.0.0.1"] + client_flags,
                    stdin=cin, stdout=cout, stderr=subprocess.STDOUT)
                client_code = client.wait(timeout=TIMEOUT)
                server_code = server.wait(timeout=TIMEOUT)
                if client_code or server_code:
                    raise RuntimeError(f"server={server_code}, client={client_code}")
            finally:
                stop(client)
                stop(server)
        for path, messages in ((server_log, at_server), (client_log, at_client)):
            output = path.read_text(encoding="utf-8")
            if "FAIL:" in output:
                raise RuntimeError(f"unexpected failure in {path}")
            for message in messages:
                if f"peer> {message}\n" not in output:
                    raise RuntimeError(f"missing received message in {path}")
    except Exception as error:
        details = "\n".join(
            f"{path.name}:\n{path.read_text(encoding='utf-8')}"
            for path in (server_log, client_log) if path.exists())
        raise RuntimeError(f"{name}: {error}\n{details}") from error
    print(f"PASS: {name}")


def reject_server_first(binary, logs):
    # Keep the port occupied to prove validation runs before socket creation;
    # both roles must fail without printing a prompt or waiting for a peer.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("0.0.0.0", 0))
        port = str(reserve.getsockname()[1])
        orders = [
            ["--udp", "--interactive", "--first", "server"],
            ["--first", "server", "--interactive", "--udp"],
        ]
        for role in ("--server", "--client"):
            for index, flags in enumerate(orders):
                result = subprocess.run(
                    [str(binary), role, "--port", port] + flags,
                    input="", text=True, encoding="utf-8", stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=3, check=False)
                name = f"reject_{role[2:]}_first_order_{index}"
                (logs / f"{name}.log").write_text(result.stdout, encoding="utf-8")
                expected = "--udp --interactive requires --first client on both peers"
                if result.returncode == 0 or expected not in result.stdout or \
                        "Interactive " in result.stdout or "you>" in result.stdout:
                    raise RuntimeError(f"{name}: incorrect rejection\n{result.stdout}")
                print(f"PASS: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build" / "rdma_message_test")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"missing binary: {binary}; build rdma-message first")
    logs = ROOT / "build" / "interactive_udp_logs"
    logs.mkdir(parents=True, exist_ok=True)
    first_client = ["--first", "client"]
    cases = [
        ("default_client_first", [], [], "reply\n", "hello\nquit\n",
         ["hello", "quit"], ["reply"]),
        ("explicit_client_first", first_client, first_client,
         "reply\n", "hello\n/quit\n", ["hello", "/quit"], ["reply"]),
        ("server_default_client_explicit", [], first_client,
         "reply\n", "hello\nquit\n", ["hello", "quit"], ["reply"]),
        ("server_explicit_client_default", first_client, [],
         "reply\n", "hello\n/quit\n", ["hello", "/quit"], ["reply"]),
        ("server_quit", [], [], "quit\n", "hello\n", ["hello"], ["quit"]),
        ("server_slash_quit", [], [], "/quit\n", "hello\n", ["hello"], ["/quit"]),
        ("client_eof", [], [], "", "", ["/quit"], []),
        ("server_eof", [], [], "", "hello\n", ["hello"], ["/quit"]),
        ("empty_line", [], [], "\n", "\nquit\n", ["", "quit"], [""]),
        ("unicode", [], [], "你好，客户端\n", "你好，服务端\nquit\n",
         ["你好，服务端", "quit"], ["你好，客户端"]),
        ("fragmented_5000_bytes", [], [], "reply\n", "x" * 5000 + "\nquit\n",
         ["x" * 5000, "quit"], ["reply"]),
    ]
    reject_server_first(binary, logs)
    for case in cases:
        exchange(binary, logs, *case)
    print(f"PASS: {len(cases) + 4} UDP interactive regressions; logs: {logs}")


if __name__ == "__main__":
    main()
