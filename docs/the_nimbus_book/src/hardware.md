# System requirements

The recommended system requirements for running the Nimbus beacon node are:

| What       |  Recommended |
| ---------- | ------ |
| Operating system | Linux [64-bit](https://en.wikipedia.org/wiki/64-bit_computing), Windows 64-bit, macOS 11+ |
| Memory     | 4GB (running) or 8GB (building) |
| Disk space | 200GB |
| Network    | Reliable broadband |

!!! note
    While the consensus client will work with a classic, spinning, hard disks, if you plan to run an execution client make sure you use an SSD, either SATA or NVMe.


### Execution client

In addition to the beacon node, you will need to run an [execution client](./eth1.md).
Check the documentation of the client of choice and add them to the above requirements.

Broadly, to run both an execution and a consensus client on the same machine, we recommend a **2 TB** SSD and **16 GB RAM**.


### Minimal requirements

Nimbus has been optimized to also run well on hardware significantly less powerful than the recommended system requirements — the more validators you run on the same node, the more hardware resources and network bandwidth will it will use.
