# DPDK_SURICATA-4_1_1

Planning to merge ACL from 3.0 with dpdk 19.11.

## Motivation

Create simple DPDK RX-TX to allow packets into SURICATA processing pipeiline mode. First step to speed up suricata open source user space application using DPDK PMD

<img src="images/arch.png" width=auto>

# Things to do

 - [ ] implement SW or HW Symmetric Hashing for reassembled packets.
 - [ ] flatten the packet buffer for full zero-copy mode.
 - [ ] use SW or HW ACL for classification on directional rules from `https://github.com/vipinpv85/DPDK-Suricata_3.0`.
 - [ ] use zero copy for paylaod, PKT decode and other layers
 - [ ] cleanup logs and debug points

# Things completed
 - allow multiple worker rather than single worker
 - allow multiple RX queue with RSS (default)
 - add dpdk fields to suricata.yaml
 - migrate to DPDk 19.11.1 LTS

## How to Build?

### dependency 
 - https://suricata.readthedocs.io/en/suricata-4.1.2/install.html
 
### version: 
| software | release |
| -- | -- |
| DPDK | dpdk-stable-18.11.1 |
| Suricata | suricata-4.1.4 |

### Build and Run

#### DPDK 18.11.3
- Download DPDK from dpdk.org.
- Untar DPDK tar file.
- Execute the following commands
```
 cd <to unatar dpdk folder>
 make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
 export RTE_SDK=$PWD
 export RTE_TARGET=x86_64-native-linuxapp-gcc
 cd x86_64-native-linuxapp-gcc
 make -j 4
```
- Test the custom build by cross checking examples like helloworld & l2fwd.

#### modified suricata:

| steps | explanation |
| -----|-----|
| `autoconf` | to build the configure script with DPDK support |
| `./configure --enable-dpdk` | makes configuration with dpdk |
| `make -j 10` | build suricata with 10 threads |

## How to Run?

| command | purpose |
| -----|-----|
| `./src/suricata --build-info; ./src/suricata --list-runmodes` | get suricata version and supported modes |
| `./src/suricata --list-dpdkports` | list DPDK available ports |
| `./src/suricata --dpdk=<path to to config>/mysuricata.cfg` | Run DPDK suircata with mysuricata.cfg |

## How to run on multiple NUMA sockets

 - DPDK API makes use of Huge pages
 - Pin the memory to per NUMA by editing EAL args
 - Pin the worker threads by eiditing affinity in suricata.yaml

```
vim mysuricata.cfg
under EAL append options '--socket-mem=1,1024' and '--scoket-limit=1,1024' for NUMA-1
vim suricata.yaml
under cpu-affinity update `worker-cpu-set` for desired NUMA-1 threads
```
