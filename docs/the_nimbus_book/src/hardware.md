# System requirements

The recommended system requirements for running the Nimbus beacon node are:

| What       |  Recommended |
| ---------- | ------ |
| Operating system | Linux [64-bit](https://en.wikipedia.org/wiki/64-bit_computing), Windows 64-bit, macOS 11+ |
| Memory     | 4GB (running) or 8GB (building) |
| Disk space | 200GB SSD |
| Network    | Reliable broadband |

!!! note
    Make sure you use a SSD, either SATA or NVMe.
    Classic, spinning, hard disks are too slow and you might not be able to finish syncing.

### Execution client

In addition to the beacon node, you will need to run an [execution client](./eth1.md).
Check the documentation of the client of choice and add them to the above requirements.

Broadly, to run both an execution and a consensus client on the same machine, we recommend a **2 TB** SSD and **16 GB RAM**.


### Minimal requirements

Nimbus has been optimized to also run well on hardware significantly less powerful than the recommended system requirements — the more validators you run on the same node, the more hardware resources and network bandwidth will it will use.
