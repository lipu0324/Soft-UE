# Soft-UE RDMA adaptation

## Scope

The update adds a transport-neutral packet channel and connects it to the existing SES/PDS queues. `PacketCodec` carries application messages with an explicit version, network byte order, length checks and CRC32. `PdsPacketCodec` carries PDS and SES headers plus the owned payload bytes. `RdmaChannel` implements bounded RC SEND/RECV using `libibverbs`; `UdpChannel` provides a software comparison path.

`PdsQueueTransport::progress()` drives one bounded bidirectional step. `PDSProcessManager` invokes that step from the normal PDS loop after `mainChk()`, so received frames enter `Net_rx_pkt_q` and are handled by the next PDS iteration. The wire codec preserves SES standard `opcode` and `version` and carries semantic response headers with and without data.

## Resource and completion rules

- Receive slots are posted before traffic and reposted after a frame is consumed.
- A send slot is reused only after its local completion.
- Queue capacities are bounded; a full inbound queue is reported as an error.
- A local send completion does not mean that the remote application has consumed the message.
- The control connection exchanges RC parameters; the message bytes use the queue pair.
- If an RDMA send completion is delayed, the send buffer and queue head remain
  owned by the outstanding operation until a later progress call observes its
  completion. A timeout therefore does not permanently stop the loop.
- A UDP server may queue an outbound frame before receiving its first packet;
  `progress()` first receives the client's frame, learns the peer, and sends
  the queued frame on the next iteration.
- PDC state is published atomically, and process-manager state lookup holds the
  same map lock used by close/remove operations.

## Validation

The source tree includes tests for framing, payload ownership, UDP messages,
UDP prequeued outbound peer learning, formal PDS loopback, and PDS queue
loopback over an active verbs device. Codec tests cover non-zero SES
`opcode`/`version` and semantic responses. The RDMA tests exercise binary
messages from zero bytes through multi-frame payloads and compare the received
bytes.

The full process-level check is:

```bash
make test-pds-process-rdma-e2e
```

It starts a server and client using the formal `PDSProcessManager` loop. The
client submits a SES request, the server receives the SYN over an RC queue
pair, creates a TPDC, forwards the payload to its SES queue, and sends the PDS
establishment ACK and real SES semantic response back to the client. The
client must observe an established IPDC and validate the response fields, and
the server must verify the request payload received by SES. The test uses
`mlx5_1` by default; pass a device name to
`scripts/test_pds_process_rdma_e2e.py` when needed.

The UDP peer-learning regression is run with:

```bash
make test-pds-udp-queue
```

The current test path uses a reliable connected queue pair. It does not validate packet loss, reordering, PDS ACK/NACK recovery, RDMA READ/WRITE, GPU memory registration, NCCL, or multi-host fabric performance. Those capabilities require separate interfaces and acceptance tests.

For a manual two-host smoke test, `rdma_message_test --interactive` provides a
turn-based terminal chat. With RDMA, the server enters the first line by default;
the client displays it and enters a reply, and `/quit` or `quit` closes the
session. Use `--first client` on both commands when the client should enter the
first line.
Pass the HCA names shown by `ibv_devices` with `--device`; an OS network
interface name is not accepted.

Build output and test logs are generated under the ignored `build/` directory.
Use `make clean` to remove those generated files before sharing a source tree;
it does not remove protocol sources, tests, documentation, or the architecture
images.

### UDP interactive mode

With `--udp --interactive`, the client is the default and only supported first
speaker: the server learns its peer address from the first received datagram.
Both peers may omit `--first` or use `--first client`. An explicit
`--first server` is rejected before opening sockets or reading terminal input,
with a message telling both peers to use `--first client`. RDMA retains its
server-first default and supports either initial speaker.

Start the server and wait for its interactive banner before starting the client:

```bash
# Terminal A
./build/rdma_message_test --server --udp --interactive --port 18515

# Terminal B
./build/rdma_message_test --client --udp --interactive \
  --peer 127.0.0.1 --port 18515
```

For two hosts, replace `127.0.0.1` with the server's IPv4 address. Either peer
can enter `quit` or `/quit` on its own turn; EOF sends `/quit` as well.

Run the loopback regression with:

```bash
make test-interactive-udp
```

This uses the existing `rdma_message_test` build and therefore needs its usual
`libibverbs` build dependencies, but it does not require an active RDMA device.
The 15 cases cover default and explicit client-first startup, mixed default and
explicit options, early rejection of server-first in either argument order,
both close commands, EOF on either peer, empty lines, UTF-8, and fragmentation.
Logs and test inputs are written to `build/interactive_udp_logs/` and are
removed by `make clean`.
