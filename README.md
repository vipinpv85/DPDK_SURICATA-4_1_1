# DPDK_SURICATA-4_1_1

Planning to merge ACL from 3.0 with dpdk 19.11.

## Motivation

Create simple DPDK RX-TX to allow packets into SURICATA processing pipeiline mode. First step to speed up suricata open source user space application using DPDK PMD

![dpdk-suricata](https://user-images.githubusercontent.com/1296097/62437531-3aef9000-b761-11e9-8c51-803cd9dddcc8.png)

# Things to do

 - [ ] allow packets to captured by Recieve and Decode threads
 - [ ] implement SW or HW Symmetric Hashing for reassembled packets.
 - [ ] flatten the packet buffer for full zero-copy mode.
 - [ ] use SW or HW ACL for classification on directional rules.

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
