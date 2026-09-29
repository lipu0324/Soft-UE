# Soft-UE RDMA adaptation

## Scope

The update adds a transport-neutral packet channel and connects it to the existing SES/PDS queues. `PacketCodec` carries application messages with an explicit version, network byte order, length checks and CRC32. `PdsPacketCodec` carries PDS and SES headers plus the owned payload bytes. `RdmaChannel` implements bounded RC SEND/RECV using `libibverbs`; `UdpChannel` provides a software comparison path.

`PdsQueueTransport::progress()` drives one bounded bidirectional step. `PDSProcessManager` invokes that step from the normal PDS loop after `mainChk()`, so received frames enter `Net_rx_pkt_q` and are handled by the next PDS iteration.

## Resource and completion rules

- Receive slots are posted before traffic and reposted after a frame is consumed.
- A send slot is reused only after its local completion.
- Queue capacities are bounded; a full inbound queue is reported as an error.
- A local send completion does not mean that the remote application has consumed the message.
- The control connection exchanges RC parameters; the message bytes use the queue pair.

## Validation

The source tree includes tests for framing, payload ownership, UDP messages, formal PDS loopback, and PDS queue loopback over an active verbs device. The RDMA tests exercise binary messages from zero bytes through multi-frame payloads and compare the received bytes.

The full process-level check is:

```bash
make test-pds-process-rdma-e2e
```

It starts a server and client using the formal `PDSProcessManager` loop. The
client submits a SES request, the server receives the SYN over an RC queue
pair, creates a TPDC, forwards the payload to its SES queue, and sends the PDS
establishment ACK back to the client. The client must observe an established
IPDC, and the server must verify the payload received by SES. The test uses
`mlx5_1` by default; pass a device name to
`scripts/test_pds_process_rdma_e2e.py` when needed.

The current test path uses a reliable connected queue pair. It does not validate packet loss, reordering, PDS ACK/NACK recovery, RDMA READ/WRITE, GPU memory registration, NCCL, or multi-host fabric performance. Those capabilities require separate interfaces and acceptance tests.
