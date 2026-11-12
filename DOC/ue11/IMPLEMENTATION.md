# UE 1.1 simulation implementation status

This branch is the first working implementation increment of the agreed M0–M8
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
- A new asynchronous SES entry point supports experimental NO_OP, SEND into a
  posted receive region, and fragmented WRITE into authorized registered memory.
  It uses the existing PDS/PDC implementation, not a replacement transport.
- Registered memory is sparse, scoped by JobID and optionally PIDonFEP, and checks
  key, access rights and overflow-safe bounds before remote writes. Revocation is
  immediate. Local unsigned-64 atomic storage primitives are tested; they are
  **not yet exposed as network atomic operations**.
- A standard-wire subset explicitly encodes Ethernet, IPv4/IPv6, native UET/UDP,
  CRC32C, RUD/ROD request headers, ACK, NACK, CP, standard SES requests and
  semantic responses. Encoding a header does not establish its complete protocol
  implementation. Connectionless delivery, CC extensions, optimized/local
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
applicable. Unsupported READ/ATOMIC requests are rejected before transmission.
Posted SEND receive completions are separate from sender completions. A timeout
does not prove that no remote bytes were written. Application code must not
destroy its own endpoint or host reentrantly from a handler; it may close them
and defer destruction to a later event.

The current native endpoint uses PIDonFEP=1, Resource Index=1, standard SES
headers and ROD. It does not implement complete relative/absolute addressing,
all required memory-key formats, immediate data, tagged matching or full
Profile message-size guarantees. Sparse storage tests at the 4GiB boundary do
not establish an end-to-end 4GiB operation guarantee. Completed incoming message
records are bounded at 4096; protocol-driven retirement and message-ID reuse
remain part of M2/M3 completion work.

Simulation addresses are generated deterministically from numeric host IDs.
`RealtimeRuntime` supplies explicit monotonic progress, but a complete real
network port and real libfabric provider remain unimplemented. The `SUP1/SUE1`
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
| M2 | Working wire subset and selected ROD recovery cases; complete RUD/UUD, all close/reuse/error paths and official process interoperability remain open. |
| M3 | Native NO_OP/SEND/WRITE and checked sparse memory; required atomic/immediate/addressing coverage and real libfabric provider remain open. |
| M4 | Basic packet-fabric substrate; congestion feedback and NSCC are not implemented. |
| M5–M8 | Not implemented; remain subsequent gated milestones. |

The implementation environment lacks CMake and the external libfabric build;
package retrieval fails with proxy HTTP 503. Make-based builds and tests are
the local validation path. CMake configuration, actual libfabric/provider ABI,
and process-level interoperability with `uet-ref-prov` must be validated in an
environment with those dependencies; they are not counted as passed here.

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
