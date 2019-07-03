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
 - run `autoconf`
 - to configure with dpdk support pass `--enable-dpdk` to `./configure`
 - to build `make -j all`
 - test with `./src/suricata --list-runmodes`

| steps | explanation |
| -----|-----|
 - run `autoconf`
 - to configure with dpdk support pass `--enable-dpdk` to `./configure`
 - to build `make -j all`
 - test with `./src/suricata --list-runmodes`

## How to Run?
 - list DPDK ports `./suricata --list-dpdkports`
 - run application `./suricata --dpdk=<path to to config>/mysuricata.cfg`
