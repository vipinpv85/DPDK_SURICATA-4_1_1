# DPDK_SURICATA-4_1_1

## Motivation

Create simple DPDK RX-TX to allow packets into SURICATA processing pipeiline mode. First step to speed up suricata open source user space application using DPDK PMD

## Purpose
integerate dpdk PMD to suricata read method under worker mode

## Planned Work

 - Run on dockers
 - ACL filtering for simplified rules
 - Packet decrypt in userspace
 - Hyperscan for rules context matching before worker thread processing.

## How To?

### version: 
 - DPDK: dpdk-stable-18.11.1
 - Suricata: suricata-4.1.4

### dependency 
 - https://suricata.readthedocs.io/en/suricata-4.1.2/install.html
