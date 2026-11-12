# Soft-UE development guidance

Soft-UE is a teaching and research implementation of the Ultra Ethernet
architecture. Preserve its SES → PDS → CMS/TSS → network/link boundaries.

- Use descriptive names for local variables and interfaces. Keep specification
  field names for wire headers, and explain abbreviations at their first use.
- Explain protocol state transitions, invariants and non-obvious calculations
  with comments and a UE 1.1 section reference. Distinguish normative behavior
  from simulator policies and intentionally unsupported features.
- Keep the original SES/PDS kernel as the protocol implementation. Do not replace
  protocol recovery with a reliable network backend or a second simulator stack.
- Drive simulation through injected integer-nanosecond clocks and events. The
  protocol path must not sleep, start threads or read wall-clock time in this mode.
- Never interpret a received address as a host pointer. All remote access must
  pass the memory registry's JobID, key, permission and bounds checks.
- Add meaningful positive, negative and boundary regressions for protocol changes.
  Record reproducible evidence and remaining gaps in DOC/ue11. Do not declare a
  profile conformant while its applicable requirements remain incomplete.
- Build with CMake/CTest; RDMA hardware dependencies must remain optional.
