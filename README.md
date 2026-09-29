# Soft-UE RDMA message path

This update adds a small, reusable message path to the Soft-UE protocol core. SES owns application bytes, PDS carries them in bounded packets, and a common packet channel can use UDP or an InfiniBand RC queue through `libibverbs`.

## Build and checks

The root `Makefile` builds into `build/`, which is ignored by Git.

```bash
make test-codec
make test-ses-payload
make test-pds-loopback
make test-pds-process-loopback
make test-core
make test-udp
make check-env
```

The RDMA checks require an active verbs device and are run separately:

```bash
make test-rdma
make test-pds-rdma-queue
```

The two-process RDMA tests use a TCP connection only to exchange queue parameters. Message bytes travel through an RC queue pair. Pass `--device <device>` to the test binary when the active device is not the default.

## Added path

- `UET/src/Network_Layer/PacketCodec.*`: versioned framing, byte order, bounds checks and CRC32.
- `UET/src/Network_Layer/PdsPacketCodec.*`: explicit PDS/SES packet encoding with owned payload bytes.
- `UET/src/Network_Layer/RdmaChannel.*`: bounded libibverbs RC SEND/RECV transport.
- `UET/src/Network_Layer/UdpChannel.*`: software transport using the same packet channel interface.
- `UET/src/Network_Layer/PdsQueueTransport.*`: bridges the PDS public queues to either transport.
- `UET/src/PDS/MessageStream.*` and `UET/src/SES/MessageEndpoint.*`: bounded fragmentation and reassembly for application messages.
- `PDSManager` and `PDSProcessManager`: drive queue transport progress from the existing PDS loop.

The path is a first integration step. It does not claim to replace the existing PDS reliability semantics, implement RDMA READ/WRITE, GPU Direct, NCCL, or a libfabric provider. RC transport validation is a local functional check and does not establish multi-host fabric connectivity or performance.
