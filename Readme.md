# **Soft**-UE: Software Prototype of Ultra Ethernet

---



[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-red?logo=apache&logoColor=white)](https://www.apache.org/licenses/LICENSE-2.0)[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/download)![C++](https://img.shields.io/badge/Language-C++-brightgreen?logo=c%2B%2B&logoColor=white&labelColor=blue)[![Soft UE Project](https://img.shields.io/badge/Ultra%20Ethernet-UE-blue?logo=ethernet&logoColor=white)](https://ultraethernet.org/)

<div align="center">
  <table>
    <tr>
      <td align="center" width="50%">
        <img src="attachment/xgs_logo_.png" alt="信工所Logo" width="180"/><br/>
        <strong>Institute of Information Engineering</strong><br/>
        Chinese Academy of Sciences<br/>
        <em>State Key Laboratory of Cyberspace Security Defense</em>
      </td>
      <td align="center" width="50%">
        <img src="attachment/wdzs_logo.png" alt="微电子所Logo" width="180"/><br/>
        <strong>Institute of Microelectronics</strong><br/>
        Chinese Academy of Sciences<br/>
        <em>Artificial Intelligence Chip and System Research and Development Center</em>
      </td>
    </tr>
  </table>
</div>

- [**Soft**-UE: Software Prototype of Ultra Ethernet](#soft-ue-software-prototype-of-ultra-ethernet)
  - [Soft-UE Overview](#soft-ue-overview)
  - [Active Feature Branches](#active-feature-branches)
  - [System Architecture](#system-architecture)
    - [Core Components](#core-components)
  - [Repository Structure](#repository-structure)
  - [Getting Started](#getting-started)
    - [System Requirements](#system-requirements)
    - [Install](#install)
    - [Test Run](#test-run)
      - [PDSTest](#pdstest)
      - [SESTest](#sestest)
    - [Writing Your Own Test Cases](#writing-your-own-test-cases)
  - [Community Contribution](#community-contribution)
  - [Contact Us](#contact-us)


## Soft-UE Overview

Soft-UE is a software prototype of [Ultra Ethernet Specification](https://ultraethernet.org/) .  Ultra Ethernet is a specification of new protocols for use over Ethernet networks and optional enhancements to existing Ethernet protocols that improve performance, function, and interoperability of AI and HPC applications. The Ultra Ethernet  specification covers a broad range of software and hardware relevant to AI and HPC workloads: from the API supported by UE-compliant devices to the services offered by the transport, link, and physical layers, as well as management, interoperability, benchmarks, and compliance requirements. This project aims to help open-source community developers better understand the Ultra Ethernet Specification while verifying its correctness and feasibility.

**Current Release:** SoftUE v1.0.0

## Active Feature Branches

The project currently has an active RDMA/libfabric prototype branch:

- [`feature/rdma-provider-prototype`](https://github.com/lipu0324/Soft-UE/tree/feature/rdma-provider-prototype): experimental UET RDMA provider work, including a libfabric provider prototype, READ/WRITE memory semantics, payload descriptor/handle support, RUD path updates, RDMA/libfabric-oriented tests, and environment/smoke scripts.

Detailed implementation and validation notes are maintained in [`README_rdma.md`](https://github.com/lipu0324/Soft-UE/blob/feature/rdma-provider-prototype/README_rdma.md) on that branch. Runtime logs, build outputs, and larger experiment evidence are intentionally kept out of the source branch.

## System Architecture

![SUETArchitecture](attachment/SUETArchitecture.png)

### Core Components

![CoreComponents](attachment/CoreComponents.png)

- **SES (Semantic Sub-layer)**: Defines endpoint addressing, authorization, message types, protocols, and semantic header formats. Operating at the transaction level (messages or RMAs), this sub-layer breaks down each transaction into multiple packets for transmission.
- **PDSManager**: Within PDS, some functions are general and others are specific to individual PDCs. Examples of general functions include the allocation of PDCs, the handling of error events that are not associated with a specific PDC, the assignment of SES packets to PDCs, etc. These services are provided by the PDS manager state machine.

- **PDC (Packet Delivery Context)**: A packet delivery context (PDC) is a dynamically established FEP-to-FEP connection that provides the context needed to implement reliability, ordering, duplicate packet elimination, and congestion management.

## Repository Structure

 ```
 UET/src/
 ├── SES/
 │   ├── SES.hpp          # SES module interface and data structures
 │   └── SES.CPP          # SES module implementation
 │
 ├── PDS/
 │   ├── PDS.hpp          # PDS core interface and helpers
 │   ├── PDC/             # PDC module (base and implementations)
 │   │   ├── PDC.hpp      # PDC class and enums
 │   │   ├── IPDC.cpp/hpp # IPDC implementation
 │   │   ├── TPDC.cpp/hpp # TPDC implementation
 │   │   └── RTOTimer/    # RTO timer
 │   └── PDS_Manager/     # PDS process manager
 │
 ├── Network_Layer/
 │   └── UDP_Network_Layer.hpp   # UDP network layer interface
 │
 ├── Transport_Layer.hpp          # Transport layer interface
 │
 ├── logger/
 │   └── Logger.hpp              # Thread-safe logger
 │
 └── Test/                       # Module test code and configs
 
 
 ```



## Getting Started

### System Requirements

- **Operating System**: Linux (Ubuntu 22.04 LTS / 24.04 LTS)  
- **Compiler**:  
  -  GCC 10.1.0 or newer  


### Install

**Step 1: Install system dependencies**

```bash
sudo apt update
sudo apt install build-essential cmake git software-properties-common
```

**Step 2: Clone the repository and navigate to its directory**

```Bash
# 1. clone the repository
git clone https://github.com/lipu0324/Soft-UE.git
# 2. navigate to the project directory
cd Soft-UE/UET/src
```

### Test Run

The project supports experimental studies at two levels of granularity: the **SES layer** and the **PDS layer**.
 For single-host evaluations, we recommend using the **software loopback link**, which is internally simulated. An optional **UDP-based network shim** is also available but disabled by default. We encourage the open-source community to build upon this work and extend it for **multi-host testing**.

You can either run the **existing test cases** used during development or **create your own**. 
```Bash
# 1. navigate to the Test directory
cd Test
# 2. compile the test cases
make help
```

#### PDSTest

The **PDS layer** is responsible for handling packet reception, dispatching each packet to its corresponding **PDC**, and processing commands and data received from the **SES layer**.
A comprehensive test of this functionality is available in `UET/src/Test/PDS_fulltest.cpp`, which verifies the following aspects:

- Establishment of an **IPDC–TPDC** connection pair
- **Packet injection and reception** through the emulated network path
- **Resource management** and automatic connection teardown

#### SESTest

**SES-layer testing** focuses on **transaction-level verification**, encompassing the transformation of **OperationMetadata** into **PDS packets**, **execution-header initialization**, and **long-message fragmentation**. Serving as a lightweight integration test, it validates the interaction between the **SES layer**, the **UDP network shim**, and the **logging infrastructure**, while invoking **PDS** and **PDC** components for data exchange.

The test suite covers the following aspects:

- **Operation metadata handling**: construction and parsing of operation requests
- **Header initialization**: population of `SES_Standard_Header` fields
- **Fragmentation logic**: generation of multiple packets for large payloads
- **UDP integration**: packet serialization and callback mechanisms

### Writing Your Own Test Cases

By invoking the classes and methods exposed at each layer—**PDS**, **PDC**, and **SES**—you can design targeted tests for specific components. Each layer defines its own input file format, and by varying the file contents, you can explore different code paths and observe runtime behavior under a wide range of conditions. We encourage the open-source community to expand the test suite to achieve broader operational coverage.


## Community Contribution

We welcome the community to contribute suggestions and improvements. This project currently covers only a portion of **UET**’s functionality, and we hope to see implementations of the remaining parts emerge through the efforts of the open-source community. At the same time, we encourage the community to raise questions about any unclear or problematic areas in the existing code, and we will do our utmost to address them.

## Contact Us

To report issues, offer suggestions, or notify us of bugs, please contact:

softuegroup@gmail.com

---

​                             **If you find this project helpful, please consider giving it a ⭐ star! Thank you so much for your support.**

​      

## RDMA/PDS Integration Update (2026-09-30)

The current implementation adds an RDMA-capable message path while keeping the
original SES, PDS, and PDC design described above. `PdsQueueTransport::progress()`
is driven by the formal `PDSProcessManager` loop; the same packet path can use a
local software loopback, UDP, or an InfiniBand RC queue through `libibverbs`.
SES payload bytes, PDS/SES headers, semantic responses, and the PDC state are
validated by the integration tests.

### Build and verification

The root `Makefile` places generated files under `build/`:

```bash
make test-codec
make test-ses-payload
make test-pds-loopback
make test-pds-process-loopback
make test-pds-process-rdma-e2e
make test-pds-udp-queue
make test-pds-rdma-queue
make test-rdma
make test-udp
make check-env
```

The formal RDMA end-to-end test uses the PDS process loop and the active
`mlx5_1` device. Its TCP connection exchanges RC queue parameters only; the
message payload travels through the RDMA queue, and the client checks the
semantic response. The UDP queue test covers a server send queue populated
before the peer is learned. The detailed adaptation notes are in
[`DOC/RDMA_ADAPTATION.md`](DOC/RDMA_ADAPTATION.md).

The original README content, logos, and architecture diagrams above remain the
project overview. This section records the additional RDMA/PDS work without
replacing that overview.

### Interactive terminal chat

For a manual two-host check, `rdma_message_test` also supports a turn-based
terminal chat. By default the server types the first line, the client replies,
and the turns continue until either side enters `/quit` or `quit`:

```bash
# Server A
./build/rdma_message_test --server --interactive \
  --first server --device <A verbs device> --port 18515

# Client B
./build/rdma_message_test --client --interactive \
  --first server --device <B verbs device> \
  --peer <A control-plane IPv4> --port 18515
```

To let the client type first, pass `--first client` on **both** commands. Both
`/quit` and `quit` close the session.

The `--device` value must be the HCA name shown by `ibv_devices` (for example
`mlx5_1`), rather than an operating-system network interface name.

All generated binaries, object files, libraries, and test logs are placed in
the ignored `build/` directory. Run `make clean` before packaging or handing
off a working tree; source files, test sources, documents, and the design
images are not affected.

```bash
make clean
```
