# UE 1.1 simulation implementation status

This branch continues the implementation of the agreed M0–M8
roadmap. It is **not a completed UE 1.1 stack** and does not claim conformance to
AI Base, AI Full, HPC or Unified Local. Native capability discovery, the scenario
validator and the machine-readable requirement inventory all keep those claims
disabled.

See [the baseline audit](BASELINE-AUDIT.md) for the actual protocol paths exercised
by each regression, concrete remaining placeholders and the next gated work.

## What runs

- The original `PDS_Manager`, `I_PDC` and `T_PDC` run with an injected nanosecond
  clock, cancellable event timers and no per-PDC/manager threads in simulation
  mode. The original SES handler is exercised separately through the explicit
  legacy-wire regression.
- A new asynchronous SES entry point supports NO_OP, SEND into a posted receive
  region, fragmented WRITE, WRITE with immediate completion data, single-packet
  DATAGRAM_SEND, and non-fetching 8/16/32/64-bit integer atomics.
  It uses the existing PDS/PDC implementation, not a replacement transport.
- Registered memory supports sparse simulation storage or locally registered application buffers, is scoped by JobID and optionally PIDonFEP/resource index, and checks
  key, access rights and overflow-safe bounds before remote writes. Revocation is
  immediate. Native integer bytes remain little endian while atomic operand fields
are encoded in network byte order, checked against an independent reference
endpoint. Network atomics support signed/unsigned integer types and min, max,
  sum, difference, product, logical/bitwise operations and atomic write. Fetching,
  compare-and-swap, floating-point types and semantic-control hints remain outside
  this increment's advertised atomic capabilities.
- A standard-wire subset explicitly encodes Ethernet, IPv4/IPv6, native UET/UDP,
  CRC32C, RUD/ROD/UUD request headers, ACK, NACK, CP, standard SES requests and
  semantic responses. Encoding a header does not establish its complete protocol
  implementation. CC extensions, optimized/local
  headers, security and IPv6 extension headers are not implemented by this codec.
- A deterministic store-and-forward fabric models directed links, serialization,
  propagation/FEC delay, bounded FIFO byte queues, tail/random packet loss,
  link up/down and shortest-hop ECMP. It does not currently implement ECN/trim
  feedback, NSCC/RCCC, LLR, CBFC/PFC, negotiated capabilities or a PHY error model.
- YAML experiments produce memory-verified results, a structured virtual-time
  trace, an Ethernet nanosecond PCAP, diagnostic protocol logs and source/spec
  provenance. The runner supports 2–64 hosts and the operations listed above.

## Build and run

Linux, GCC with C++17, Make and Python 3.9+ with PyYAML are sufficient for the
dependency-light implementation. No RNIC, libibverbs, libfabric or privileged
socket is required for these simulations.

```sh
make -j2 simulation
make test-sim
make test-scenarios
python3 scripts/run_simulation.py examples/simulation/two-host.yaml --output build/two-host
python3 scripts/run_simulation.py examples/simulation/leaf-spine.yaml --output build/leaf-spine
make test
```

An equivalent out-of-tree CMake/CTest build is provided:

```sh
cmake -S . -B build/cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build/cmake -j2
ctest --test-dir build/cmake --output-on-failure
```

The existing RC adapter remains optional. Use `SOFTUE_ENABLE_RDMA=ON` with CMake
or `ENABLE_RDMA=1` with Make when the libibverbs development files are installed.
A UDP-only build explicitly rejects an attempted RDMA connection; it never
substitutes a fake RDMA backend. The old UDP and interactive chat tests remain
available in the default build.

For sanitizer verification, use CMake's `SOFTUE_ENABLE_SANITIZERS=ON`, or:

```sh
make BUILD=build/asan \
  CXXFLAGS='-std=c++17 -O1 -g -pthread -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDLIBS='-fsanitize=address,undefined' build/asan/softue_sim
python3 scripts/test_simulation.py --binary build/asan/softue_sim
```

## Interfaces and current limits

`Runtime::Services` injects `IClock`, `ITimerQueue`, a deferred wake callback and
the simulation RTO base. `PdsHost` owns the protocol manager and port binding;
`SES::Endpoint` owns native operation state, receive postings and MR authority.
Destroy/close the endpoint before its host; host, port and runtime references
must remain alive for their dependents. They are non-copyable and simulation
calls are serialized by the event loop.
`IPacketPort` reports synchronous send acceptance and writable readiness after
`WouldBlock`; the host retains blocked frames and resumes through a deferred
wake callback without polling. Closing a host detaches both callbacks.

`Endpoint::submit()` returns an operation ID; `poll_completion()` returns one
completion per local operation, with a caller context and remote status where
applicable. Unsupported READ requests and unadvertised atomic operations/types
are rejected before transmission. `LocalSuccess` for UUD means the local port
accepted the datagram; it makes no claim about target receipt. `Success` for a
reliable operation follows the semantic response. WRITE immediate data is
delivered through a separate target completion without consuming a SEND receive.
Posted SEND receive completions are separate from sender completions. A timeout
does not prove that no remote bytes were written. Application code must not
destroy its own endpoint or host reentrantly from a handler; it may close them
and defer destruction to a later event.

The default native endpoint exposes PIDonFEP=1 and Resource Index=1. Its resource
directory also supports explicit relative-PID mappings, node-wide absolute PIDs,
independent SEND/tagged/RMA index spaces, generation and disabled-resource checks.
Absolute PID selection still uses checked zero-based buffer offsets; it does not
turn a received number into a host pointer. MRs can authorize one JobID or any
valid JobID, and can bind a specific resource index (including index zero).
All required memory-key classes, tagged operations and full Profile acceptance
remain open. A streamed native WRITE of 4 GiB−1 has been transmitted and checked
end to end; this does not establish all large-message operations or Profile conformance.

`Operation::payload_source` accepts a local, shared `PayloadSource` instead of an
eager vector. The endpoint reads at most its configurable producer window (eight
fragments by default) ahead of PDS transmission. PDS retains its own outstanding
packets and retransmits cached bytes without calling the application reader
again. `StoragePayload` keeps a local storage object alive; borrowed application
buffers must remain valid and unchanged until completion. Error completion stops
all further application reads and uses one reliable EOM `MSG_ERROR` for an unsent
tail; a timeout alone does not establish that no remote bytes were placed.
Generated payload readers
must be deterministic, nonblocking and nonreentrant. Received adjacent byte
intervals coalesce; unallocated all-zero sparse pages stay unallocated, while
writes still clear previously stored bytes.

The full boundary experiment is separate from the fast CTest regression:

```sh
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target streaming_payload_test -j2
build/release/streaming_payload_test --bytes 4294967295
# Or preserve the source commit, binary hash, log and executor measurements:
python3 scripts/test_large_message.py --binary build/release/streaming_payload_test --output build/large-message
```

It sends 524,288 actual 8192-byte-or-smaller fragments through the original
protocol and fabric, then verifies completion length, beginning/middle/end
markers, cleared old bytes, message retirement and timer cleanup. The observed
producer peak is eight fragments, the ordered receiver retains one interval,
and only three sparse pages are allocated. The default regression also tests
8 MiB, packet-loss recovery, permanent loss and rejection of 4 GiB before reading
the payload. These are correctness experiments, not hardware throughput results.
The `large message boundary` GitHub workflow runs this experiment nightly on the
default branch and supports manual dispatch once available there. It preserves
the report and log as an artifact; ordinary pull-request CI retains the smaller
streaming and loss regressions. Adding the workflow does not mean its scheduled
run has already executed.

PDS publishes local events for transmit PSNs, peer CACKs, receive Clear and
connection termination. SES uses these to retire completed receive records and
lease message IDs until all fragments through EOM are cleared. A 66,000-operation
regression crosses the full 16-bit message-ID space. An intermediate packet's
DEFAULT_RESPONSE cannot complete a message; successful completion requires EOM transmission and either an explicit full-length
response or the default response associated with the EOM PSN. In RUD the explicit
full-length response may accompany a later gap-filling packet. Early error completion retains the ID while fragments remain.

SES retains the first error through EOM and Clear. Later packets of the rejected
message cannot consume a new posting or access memory, even when resource state
changes. Initiator-error and `MSG_ERROR` packets do not access memory; RUD may
deliver the termination before SOM, and a later SOM still supplies the header
data for the target error completion. Local payload-reader exceptions generate
`MSG_ERROR` and a local error completion. SEND truncation consumes its posting,
places zero bytes, and reports a target `Truncated` completion with the original
length. The provider maps this to `FI_ETRUNC` and `olen`.

Per-message receive bookkeeping defaults to 4096 records. If it fills, the local
simulator policy refuses new messages on that PDC until it closes, while existing
records can finish. This conservative refusal is bounded by the PDC count and
never silently evicts an error record. This conservative bookkeeping exhaustion
policy is separate from unexpected-payload capacity and full acceptance remains open.

ROD SEND now buffers unmatched messages in acceptance order under a configurable
logical-byte budget (256 KiB by default). A late posting can place a complete or
partially buffered message through the ordinary MR checks. Delivery completion
waits for placement; the actual EOM request remains in SES processing meanwhile.
Payload exhaustion disables the SEND index using the client/server generation
mechanism of §3.4.4.7.3.2. Posting resources increments the generation and enables
the index, while previously accepted messages drain under their saved selection.
RUD unmatched SEND returns NO_MATCH with zero modified length.

`Endpoint::transport_pending(operation)` includes both application-pending and
leased-ID state, so a caller can wait for the previous attempt to retire before
retrying. The provider uses it for bounded recoverable-error retries and
conservative ordered admission; see [its recovery policy](PROVIDER.md). A PDC
termination also produces one error completion for an unfinished matched target
receive, with the number of bytes already placed.

`PdsHost::request_connection_close()` accepts either local PDC role. An initiator
quiesces and sends Close Command; a target schedules one Close Request, consumes
a fresh return-direction PSN and retains it in the PDS TX cache. Lost requests
and plain ACKs recover with the same PSN and RETX set. An acknowledged request
waits for the initiator's Close Command; an unacknowledged request eventually
terminates in error under the configured PDS retry budget. Repeated local
requests and duplicate wire requests do not restart the handshake. The standard
initiator requires the Close Command CP_ACK payload, so a plain ACK with the
same PSN cannot cancel close recovery. ROD/RUD loss, silent-peer and stripped
CP_ACK tests exercise these transitions; other control variants remain open.

`PdsHost::open_connection(peer, job, mode, negotiation)` can establish a ROD/RUD
transport with a NOOP CP or a `NO_NEG` Negotiation CP before submitting an SES
operation. This generates no synthetic semantic request or application
completion. Numbered CPs share the request PSN window. The following WRITE uses
the established tuple and next PSN; lost SYN CPs use the same safety wait as lost
SYN data requests. NO_NEG carries its required 32 zero payload bytes. The codec
also parses length-delimited on-off negotiation payloads; this implementation
responds with a plain ACK and enables no optional negotiated feature.

ACK Request handling distinguishes a cached guaranteed response, a packet still
being processed by SES, a processed default response and a packet not received.
It replays the cached response, reports `UET_RCVD_SES_PROCG` or
`UET_PKT_NOT_RCVD` as appropriate, and silently drops requests below Clear.
Tests include the 32-bit sequence wrap. Probe/Credit/PCM and negotiated SYN
safety transfer remain outside this increment's protocol capability claims.

Simulation addresses are generated deterministically from numeric host IDs.
`RealtimeRuntime` and `UdpFramePort` provide explicit monotonic and nonblocking
socket progress. The outer UDP tunnel carries unchanged Ethernet/UE frames and
adds no reliability. Two independent processes exercise IPv4/native and IPv6/UDP,
registered host buffers, packet/response loss and error completion. Synchronize
real time before submitting operations after application setup or an input wait.
The optional experimental libfabric provider uses this same path; see
[its API and transport limits](PROVIDER.md). The `SUP1/SUE1`
transport is retained only through explicitly selected legacy APIs; it is not
silently detected or accepted by the standard-wire path.

The initial YAML runner uses disjoint target ranges so it can independently
verify final memory. It accepts one SEND posting per target/JobID; arbitrary
receive ordering, overlapping writes and negative memory tests use the C++ API.
FIFO queues and zero protocol-processing delay are model assumptions. Timing
results are simulation parameters, not calibrated hardware performance.

## Milestone accounting

| Milestone | State in this increment |
|---|---|
| M0 | Fixed baselines, reviewed initial inventory, normative-candidate extraction, regression/build/report tools. Full clause-by-clause review remains open. |
| M1 | Working virtual runtime connected to original protocol state machines, cancellation/lifetime tests and replayable scenarios. |
| M2 | ROD go-back-N, RUD selective recovery/window/duplicate tests, UUD local completion, normal/lossy close, signed PSN offsets and independent reference parser/CRC comparisons. Connection reuse, SYN safety, stale-packet rejection, resource recovery, UE 1.1 Close CP ACK and a shared reference process path are covered. The full control/error/wrap matrix and CC ACK variants remain open. |
| M3 | Native NO_OP/SEND/WRITE/WRITE immediate/DATAGRAM_SEND and integer non-fetching atomics. Relative/absolute selection, retirement, first-error handling, bounded ROD unexpected messages and generation recovery are covered. The experimental FI_MSG/WRITE/integer-atomic/DGRAM provider includes recoverable-error retries. Remaining MR key classes, API flags and acceptance remain open. |
| M4 | Basic packet-fabric substrate; congestion feedback and NSCC are not implemented. |
| M5–M8 | Not implemented; remain subsequent gated milestones. |

Network access was restored on 2026-11-12. CMake/CTest, libfabric 2.0.0 and the
pinned reference's `libuet_fabric.so`/`uet` application now build successfully.
The optional `softue` libfabric provider now loads and runs public fi_* calls.
The current executor has no CAP_NET_RAW. An independent process test therefore
links unchanged reference SES/PDS code with a test-only NIC override that carries
frames over unprivileged sockets. It verifies WRITE/SEND, a non-fetching uint64 SUM, a return SEND and Clear
retirement. Raw-socket/veth interoperability remains separate and unverified.

The optional independent comparison builds a small C harness against the reference
library, without linking the Soft-UE codec into that harness:

```sh
cmake -S . -B build/reference \
  -DSOFTUE_REFERENCE_ROOT=/path/to/uet-ref-prov \
  -DSOFTUE_LIBFABRIC_ROOT=/path/to/libfabric-2.0.0
cmake --build build/reference -j2
ctest --test-dir build/reference -R "reference_wire_comparison|reference_process_interop" --output-on-failure
```

It checks 24 native/UDP and IPv4/IPv6 fixtures across RUD, ROD, UUD, ACK, NACK
and CP, including signed CLEAR/ACK offsets and CRC network byte order. It also
rejects a corrupted payload. The pinned reference remains an external dependency;
its private headers are used only by the optional reference test targets. The process test changes only the NIC boundary, not reference SES/PDS code. The pinned reference uses an older close-ACK format and is not an oracle for the UE 1.1 CP_ACK payload.

## Traceability and normative review

The fixed inputs are UE Specification 1.1 (2026-10-12), Soft-UE
`4a4e6d874909720097b1ae20302a538a97116976`, and uet-ref-prov
`5b4e0491329b8e28764bca6847e2f6a0eaa84b9b`. The uploaded PDF SHA256 is
`4c8436ec7daa627ad6cce0680bea66cfac496dfe4e217631064e68acafe04531`.

```sh
python3 scripts/check_requirements.py --output build/conformance.json
pdftotext -layout UE-Specification-1.1.pdf build/ue11.txt
python3 scripts/extract_spec_requirements.py --text build/ue11.txt --output build/ue11-candidates.json
```

All extracted candidates require manual normative/informative, conditional and
Profile classification. The inventory deliberately remains incomplete; the
checker rejects Profile claims until the inventory and applicable requirements
are verified. A `verified` implementation task such as deterministic replay is
not an assertion of UE compliance.

Known specification/reference differences requiring explicit review:

- Section 3.3 defines four Profiles; section 8 retains old three-Profile wording.
  Use section 3.3 for this roadmap and record the inconsistency.
- Table 3-4 labels the semantic response as 16 bytes, while section 3.4.3.7's
  detailed field widths total 12 bytes and the pinned reference uses 12. The
  current subset follows the detailed field format; this is recorded rather
  than hidden as a blanket conformance claim.
- The pinned reference documents its congestion implementation as partial and
  based on v0.6; it cannot be treated as a complete UE 1.1 oracle.
- Native original SES enums/version values and private framing differ from the
  standard. The new wire interface uses explicit standard encodings, and its
  version-zero native endpoint is separate from legacy version-two tests.

New standard codec/runtime/storage code is independently implemented. This
increment does not copy the reference implementation's cryptographic keys,
algorithms or test-vector files into Soft-UE.
