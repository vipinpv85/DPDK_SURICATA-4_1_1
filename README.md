# DPDK_SURICATA-4_1_1

## Motivation

Create simple DPDK RX-TX to allow packets into SURICATA processing pipeiline mode. First step to speed up suricata open source user space application using DPDK PMD

## How to Build?

### dependency 
 - https://suricata.readthedocs.io/en/suricata-4.1.2/install.html
 
### version: 
 - DPDK: dpdk-stable-18.11.1
 - Suricata: suricata-4.1.4

### Build and Run

#### DPDK 18.11.3
- Download DPDK from dpdk.org.
- Untar DPDK and use make config `T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc`.
- Execute `export RTE_SDK=$PWD; export RTE_TARGET=x86_64-native-linuxapp-gcc; cd x86_64-native-linuxapp-gcc, make -j 4`.
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
| `./src/suricata --list-runmodes` | list DPDK available ports |
| `./src/suricata --dpdk=<path to to config>/mysuricata.cfg` | Run DPDK suircata with mysuricata.cfg |
