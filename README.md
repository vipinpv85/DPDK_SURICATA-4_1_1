# DPDK_SURICATA-4_1_1

## Motivation

Create simple DPDK RX-TX to allow packets into SURICATA processing pipeiline mode. First step to speed up suricata open source user space application using DPDK PMD

## How to Build?

### dependency 
 - https://suricata.readthedocs.io/en/suricata-4.1.2/install.html
 
### version: 
 - DPDK: dpdk-stable-18.11.1
 - Suricata: suricata-4.1.4

### modified suricata:
 - run `autoconf`
 - to configure with dpdk support pass `--enable-dpdk` to `./configure`
 - to build `make -j all`
 - test with `./src/suricata --list-runmodes`
