/*
 * Copyright (c) 2019 Vipin Varghese
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.You can copy, redistribute or modify this Program under the terms of
 */

/** 
 * \file
 *
 * \author Vipin Varghese <vipinpv85@gmail.com>
 *
 * DPDK runmode support
 */

//#include "dpdk-include-common.h"

#ifdef HAVE_DPDK
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_acl.h>
#include <rte_version.h>
#include <rte_tailq.h>
#include <rte_cfgfile.h>
#endif

#include "source-dpdk.h"

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-dpdk.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"

#ifdef HAVE_DPDK

enum {
    PROTO_FIELD_IPV4,
    SRC_FIELD_IPV4,
    DST_FIELD_IPV4,
#if DPDK_FUTURE
    SRCP_FIELD_IPV4,
    DSTP_FIELD_IPV4,
#endif
    NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4 classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
    RTE_ACL_IPV4_PROTO,
    RTE_ACL_IPV4_SRC,
    RTE_ACL_IPV4_DST,
    RTE_ACL_IPV4_PORTS,
    RTE_ACL_IPV4_NUM
};
/*
 --- ipv4 ---
        src ip 3
        dst ip 7
        sport 11
        dport 13
 --- ipv6 ---
         src ip 2
         dst ip 18
         sport ip 34
         dport ip 36
 */

static struct rte_acl_field_def ip4_defs[NUM_FIELDS_IPV4] = {
    [0] = {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PROTO,
    .offset = 0,
    },
    [1] = {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = sizeof(uint32_t),
    .field_index = SRC_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_SRC,
    //.offset = offsetof(struct ipv4_hdr, src_addr) - offsetof(struct ipv4_hdr, next_proto_id),
    .offset = 3,
    },
    [2] = {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = sizeof(uint32_t),
    .field_index = DST_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_DST,
    //.offset = offsetof(struct ipv4_hdr, dst_addr) - offsetof(struct ipv4_hdr, next_proto_id),
    .offset = 8,
    },
#if DPDK_FUTURE
    [3] = {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PORTS,
    .offset = 12,
    },
    [4] ={
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PORTS,
    .offset =  14,
    },
#endif
};

enum {
    IP6_PROTO,
    IP6_SRC0,
    IP6_SRC1,
    IP6_SRC2,
    IP6_SRC3,
    IP6_DST0,
    IP6_DST1,
    IP6_DST2,
    IP6_DST3,
#if DPDK_FUTURE
    IP6_SRCP,
    IP6_DSTP,
#endif
    IP6_NUM
};

#define IP6_ADDR_SIZE 16
static struct rte_acl_field_def ip6_defs[IP6_NUM] = {
    {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = IP6_PROTO,
    .input_index = IP6_PROTO,
    .offset = 0,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_SRC0,
    .input_index = IP6_SRC0,
    .offset = 2,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_SRC1,
    .input_index = IP6_SRC1,
    .offset = 6,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_SRC2,
    .input_index = IP6_SRC2,
    .offset = 10,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_SRC3,
    .input_index = IP6_SRC3,
    .offset = 14,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_DST0,
    .input_index = IP6_DST0,
    .offset = 18,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_DST1,
    .input_index = IP6_DST1,
    .offset = 22,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_DST2,
    .input_index = IP6_DST2,
    .offset = 26,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE/*RTE_ACL_FIELD_TYPE_MASK*/,
    .size = 4,
    .field_index = IP6_DST3,
    .input_index = IP6_DST3,
    .offset = 30,
    },
#if DPDK_FUTURE
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = IP6_SRCP,
    .input_index = IP6_SRCP,
    .offset = 34,
    },
    {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = IP6_DSTP,
    .input_index = IP6_SRCP,
    .offset = 36,
    }
#endif
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ip4_defs));
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ip6_defs));

#define SUIRCATA_DPDK_MAXARGS 32

static DpdkMempool_t dpdk_mempool_config;
static DpdkAclConfig_t dpdk_acl_config;
static DpdkConfig_t dpdk_config;
static DpdkPortConfig_t dpdk_ports[RTE_MAX_ETHPORTS];

/* Number of configured parallel pipelines. */
static int dpdk_num_pipelines;

static uint16_t inout_map_count = 0;

static struct acl4_rule testv4;
static struct acl6_rule testv6;

uint16_t argument_count = 1;
char argument[SUIRCATA_DPDK_MAXARGS][32] = {{"./dpdk-suricata"}, {""}};

static uint16_t
dpdk_mbuf_ptype_fiter_nonip(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused);

static uint16_t
dpdk_sw_fiter_nonip(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused);

#endif

/*
 * runmode support for dpdk
 */

static const char *dpdk_default_mode = "workers";

const char *RunModeDpdkGetDefaultMode(void)
{
	SCEnter();
	return dpdk_default_mode;
}

void RunModeDpdkRegister(void)
{
	SCEnter();
#ifdef HAVE_DPDK
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "workers",
                              "Workers dpdk mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeDpdkWorkers);
    dpdk_default_mode = "workers";
#endif

	return;
}

int CreateDpdkRing(void)
{
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
	return -1;
#else
	int i, ring_index = 0;
	char ring_name[25] = {""};

	SCLogNotice(" Creating (%d) Rings!", dpdk_num_pipelines);

	for (i = 0; i < dpdk_num_pipelines; i++)
	{
		sprintf(ring_name, "SCRING%d", i);
		SCLogDebug(" ring create for %s", ring_name);

		if (rte_ring_lookup(ring_name) == NULL) {
			struct rte_ring *ptr = rte_ring_create(ring_name, 8192/*size*/, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
			if (ptr == NULL) {
				SCLogError(SC_ERR_DPDK_MEM, " failed to create (%s) RING!", ring_name);
				return -1;
			}
		}
	}
	SCLogDebug(" RING setup done");

	SCLogDebug(" Map port to ring");

	RTE_ETH_FOREACH_DEV(i)
	{
		struct rte_eth_dev_info dev_info;

		rte_eth_dev_info_get(i, &dev_info);

		for (int j = 0; j < dev_info.nb_rx_queues; j++) 
		{
			sprintf(ring_name, "SCRING%d", ring_index++);
			dpdk_config.port_ring[i][j] = rte_ring_lookup(ring_name);

			SCLogDebug(" dpdk_config.port_ring for port %u queue %u is %p", i, j, dpdk_config.port_ring[i][j]);
		}
	}

	return 0;
#endif
}

int SetupDdpdkPorts(void)
{
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
#else
	SCLogDebug(" port setup!");

	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	uint16_t mtu = 0;
	int i, j;

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
			.split_hdr_size = 0,
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = ETH_RSS_IP,
			},
		},
	};

	/* create mbuf_pool if not created */
	if (rte_mempool_lookup(dpdk_mempool_config.name) == NULL) {
		dpdk_mempool_config.mbuf_ptr = rte_pktmbuf_pool_create(
				dpdk_mempool_config.name, dpdk_mempool_config.n,
				/* MEMPOOL_CACHE_SIZE*/ 256,
				(dpdk_mempool_config.private_data_size == 0)? sizeof(Packet):dpdk_mempool_config.private_data_size,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				dpdk_mempool_config.socket_id);
	}

	if (dpdk_mempool_config.mbuf_ptr == NULL) {
		SCLogError(SC_ERR_DPDK_CONFIG, "Failed to create mbuf pool!\n");
		return -EINVAL;
	}
	SCLogDebug(" mbuf pool (%p)!\n", rte_mempool_lookup(dpdk_mempool_config.name));

	RTE_ETH_FOREACH_DEV(i) {
		SCLogDebug(" port index %d!\n", i);

		struct rte_eth_dev_info dev_info;
		struct rte_eth_conf local_port_conf = port_conf;
		uint64_t rx_offloads = local_port_conf.rxmode.offloads;

		if (dpdk_ports[i].jumbo) {
			rx_offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
		}
		local_port_conf.rxmode.offloads = rx_offloads;

		rte_eth_dev_info_get(i, &dev_info);
		if (rte_eth_dev_adjust_nb_rx_tx_desc(i, &nb_rxd, &nb_txd) < 0) {
			SCLogError(SC_ERR_DPDK_CONFIG, "Failed to adjust port (%d) descriptor for rx and tx!", i);
			return -EINVAL;
		}

	nb_rxd = 1024;
	nb_txd = 1024;
	dpdk_ports[i].rxq_count = (dpdk_ports[i].rxq_count == 0) ? 1 : dpdk_ports[i].rxq_count;
	dpdk_ports[i].txq_count = (dpdk_ports[i].txq_count == 0) ? 1 : dpdk_ports[i].txq_count;

		if (dpdk_ports[i].rxq_count == 1) {
			local_port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
		} else {

			local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
			if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
				SCLogInfo(" Port %u modified RSS hash function based on hardware support,"
						"requested:%#"PRIx64" configured:%#"PRIx64,
						i,
						port_conf.rx_adv_conf.rss_conf.rss_hf,
						local_port_conf.rx_adv_conf.rss_conf.rss_hf);

				if (local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0)
					return -EINVAL;
			}
		}

		if (rte_eth_dev_configure(i, dpdk_ports[i].rxq_count, dpdk_ports[i].txq_count, &local_port_conf) < 0) {
			SCLogError(SC_ERR_DPDK_CONFIG, "Failed to configure port [%d]", i);
			return -EINVAL;
		}

		for (j = 0; j < dpdk_ports[i].rxq_count; j++) {
			if (rte_eth_rx_queue_setup(i, j, nb_rxd, rte_eth_dev_socket_id(i), NULL, dpdk_mempool_config.mbuf_ptr) < 0) {
				SCLogError(SC_ERR_DPDK_CONFIG, "Failed to setup port [%d] rx_queue: %d.", i, dpdk_ports[i].rxq_count);
				return -EINVAL;
			}

			dpdk_num_pipelines += 1;
		}

		for (j = 0; j < dpdk_ports[i].txq_count; j++) {
			if (rte_eth_tx_queue_setup(i, j, nb_txd, rte_eth_dev_socket_id(i), NULL) < 0) {
				SCLogError(SC_ERR_DPDK_CONFIG, "Failed to setup port [%d] tx_queue: %d.", i, dpdk_ports[i].txq_count);
				return -EINVAL;
			}
		}

		if (rte_eth_dev_get_mtu (i, &mtu) != 0) {
			SCLogError(SC_ERR_DPDK_CONFIG, "Failed to fetch mtu for port [%d]", i);
			return -EINVAL;
		}

		if (mtu != dpdk_ports[i].mtu) {
			if (rte_eth_dev_set_mtu (i, mtu) != 0) {
				SCLogError(SC_ERR_DPDK_CONFIG, "Failed to set mtu (%u) for port [%d]", mtu, i);
				return -EINVAL;
			}
		}

		rte_eth_promiscuous_enable(i);

		/* add call back to filter non-ip packets */
		uint32_t ptypes[16];
		uint32_t ptype_mask = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6;

		int hw_filter = 0;
		int num_ptypes = rte_eth_dev_get_supported_ptypes(i, ptype_mask, ptypes, RTE_DIM(ptypes));
		if (num_ptypes > 0) {
			for (int j =0; j < num_ptypes; j++) {
				hw_filter = (uint8_t)((ptypes[j] & RTE_PTYPE_L4_UDP) == RTE_PTYPE_L4_UDP);
				if (hw_filter)
					break;
			}

			if (hw_filter) {
				if (rte_eth_dev_set_ptypes(i, ptype_mask, &ptypes[j], 1) != 0) {
					hw_filter = 0;
				}
			}
		}

		for (int q = 0; q < dpdk_ports[i].rxq_count; q++) {
			if (rte_eth_add_rx_callback(i, q, (hw_filter) ?
				dpdk_mbuf_ptype_fiter_nonip: dpdk_sw_fiter_nonip, NULL) == NULL) {
				SCLogError(SC_ERR_DPDK_CONFIG, "Failed to configure callback on port (%d)!", i);
				return -EINVAL;
			}
		}

		/* add call back to pre-filter ACL */
	}

#if 0
		/* check if enough lcore are present to run the logic */
		if ( >= rte_lcore_count()) {
			SCLogError(SC_ERR_DPDK_CONFIG, "Expects (%d) lcores for (%d) port, availble lcores (%d)!", GetDpdkPort());
			return -EINVAL;
		}
#endif

#endif

	return 0;
}

int ValidateDpdkConfig(void)
{
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
#else
	SCLogDebug(" ports %u\n!", GetDpdkPort());

	struct rte_eth_link link1, link2;
	int ports = GetDpdkPort();

	if (ports) {
		/* port setup */
		if (SetupDdpdkPorts() != 0) {
			SCLogError(SC_ERR_DPDK_CONFIG, " Failed to setup Ports!");
			return -1;
		}

		/* if mode is BYPASS|IPS 
		 * - check for different in-out
		 * - check for same speed
		 */
		if (
					(dpdk_config.mode == 0 /*BYPASS*/) ||
					(dpdk_config.mode == 2 /*IPS*/) ||
					(dpdk_config.mode == 3 /*HYBRID*/)) {
				for (int j = 0; j < inout_map_count; j++)
				{
					if (dpdk_config.portmap[j][0] == dpdk_config.portmap[j][1]) {
						SCLogError(SC_ERR_DPDK_CONFIG, " Mode (%u); port in (%u) out (%u) is same",
							dpdk_config.mode, dpdk_config.portmap[j][0], dpdk_config.portmap[j][1]);
						return -1;
					}

					rte_eth_link_get(dpdk_config.portmap[j][0], &link1);
					rte_eth_link_get(dpdk_config.portmap[j][1], &link2);

					if ((link1.link_speed != link2.link_speed) ||
							(link1.link_duplex != link2.link_duplex)) {
						SCLogNotice("\n -- Mismatch in Port Config --\n"
								" - Ingress (%d) Egress (%d)\n"
								" - speed (%u) (%u)\n"
								" - duplex (%u) (%u)\n"
								" - autoneg (%u) (%u)\n"
								" - status (%u) (%u)\n",
								dpdk_config.portmap[j][0], dpdk_config.portmap[j][1],
								link1.link_speed, link2.link_speed,
								link1.link_duplex, link2.link_duplex,
								link1.link_autoneg, link2.link_autoneg,
								link1.link_status, link2.link_status);
					}
				}
		} else
		/* if mode is IDS 
		 * - check port map are same
		 */
		if (dpdk_config.mode == 1 /*IDS*/) {
				for (int j = 0; j < inout_map_count; j++)
				{
					if (dpdk_config.portmap[j][0] == dpdk_config.portmap[j][1]) {
						SCLogWarning(SC_WARN_PROFILE, " Mode (%u); port in (%u) out (%u)\n",
							dpdk_config.mode,  dpdk_config.portmap[j][0], dpdk_config.portmap[j][1]);
					}

					rte_eth_link_get(dpdk_config.portmap[j][0], &link1);
					rte_eth_link_get(dpdk_config.portmap[j][1], &link2);

					SCLogDebug(" -- Port Config --\n"
							" - Ingress (%d)\n"
							" - speed (%u)\n"
							" - duplex (%u)\n"
							" - autoneg (%u)\n"
							" - status (%u)\n",
							dpdk_config.portmap[j][0],
							link1.link_speed,
							link1.link_duplex,
							link1.link_autoneg,
							link1.link_status);
				}
		}
	} else {
		SCLogError(SC_ERR_DPDK_CONFIG, " no ports");
		return -1;
	}
#endif

	return 0;
}

int CreateDpdkReassemblyFragement(void)
{
	int ret = 0;
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
#else
	if (dpdk_config.rx_reassemble)
		SCLogDebug(" Reassembly enable!");
	else
		SCLogDebug(" Reassembly disable!");

	if (dpdk_config.tx_fragment)
		SCLogDebug(" Fragement enable!");
	else
		SCLogDebug(" Fragement disable!");
#endif

	return ret;

}

int CreateDpdkAcl(void)
{
	int ret = 0;
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
#else
	if (dpdk_config.pre_acl) {
		SCLogDebug(" PRE-ACL to create!");

		struct rte_acl_param acl_param;
		struct rte_acl_ctx *ctx;

		acl_param.socket_id = 0;
		acl_param.max_rule_num = dpdk_acl_config.acl4_rules;

		/* setup acl - IPv4 */
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ip4_defs));
		acl_param.name = "suricata-ipv4";
		ctx = rte_acl_create(&acl_param);
		if ((ctx == NULL) || (rte_acl_set_ctx_classify(ctx, RTE_ACL_CLASSIFY_SSE))) {
			SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "acl ipv4 fail!!!");
			exit(EXIT_FAILURE);
		}
		SCLogNotice("DPDK ipv4AclCtx: %p done!", ctx);
		dpdk_acl_config.ipv4AclCtx = (void *)ctx;

		/* setup acl - IPv6 */
		acl_param.max_rule_num = dpdk_acl_config.acl6_rules;
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ip6_defs));
		acl_param.name = "suricata-ipv6";
		ctx = rte_acl_create(&acl_param);
		if ((ctx == NULL) || (rte_acl_set_ctx_classify(ctx, RTE_ACL_CLASSIFY_SSE))){
		SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "acl ipv6 fail!!!");
		exit(EXIT_FAILURE);
		}
		SCLogNotice("DPDK ipv6AclCtx: %p done!", ctx);
		dpdk_acl_config.ipv6AclCtx = (void *)ctx;
	}
	else
		SCLogDebug(" PRE-ACL need not to create!");

	if (dpdk_config.post_acl)
		SCLogDebug(" POST-ACL to create!");
	else
		SCLogDebug(" POST-ACL need not to create!");
#endif

	return ret;
}

int ParseDpdkYaml(void)
{
	int ret = 0;

	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK");
#else
	SCLogDebug(" configured for Dpdk");

	const char dpdk_components[10][40] = {
			"pre-acl", "post-acl",
			"rx-reassemble", "tx-fragment",
			"mode", "input-output-map"
			};
	SCLogDebug(" elements in yaml for dpdk: %d", (int) RTE_DIM(dpdk_components));

	ConfNode *node = ConfGetNode("dpdk");
	if (node == NULL) {
		SCLogError(SC_ERR_DPDK_CONFIG, "Unable to find dpdk in yaml");
		return -SC_ERR_DPDK_CONFIG;
	}

	ConfNode *sub_node = NULL;

	TAILQ_FOREACH(sub_node, &node->head, next) {
		SCLogDebug(" sub_node (%s) node (%s)", sub_node->name, node->name);

		for (unsigned long int i = 0; i < RTE_DIM(dpdk_components); i++) {
			if (strcasecmp(dpdk_components[i], sub_node->name) == 0) {
				SCLogDebug(" sub_node (%s) val (%s)", sub_node->name, sub_node->val);

				if (strcasecmp("pre-acl", sub_node->name) == 0) {
					dpdk_config.pre_acl = (strcasecmp("yes", sub_node->val) ? 1 : 0);
					continue;
				} else if (strcasecmp("post-acl", sub_node->name) == 0) {
					dpdk_config.post_acl = (strcasecmp("yes", sub_node->val) ? 1 : 0);
					continue;
				} else if (strcasecmp("rx-reassemble", sub_node->name) == 0) {
					dpdk_config.rx_reassemble = (strcasecmp("yes", sub_node->val) ? 1 : 0);
					continue;
				} else if (strcasecmp("tx-fragment", sub_node->name) == 0) {
					dpdk_config.tx_fragment = (strcasecmp("yes", sub_node->val) ? 1 : 0);
					continue;
				} else if (strcasecmp("mode", sub_node->name) == 0) {
					dpdk_config.mode = (
							(strcasecmp("IDS", sub_node->val) == 0)? 1 :
							(strcasecmp("IPS", sub_node->val) == 0) ? 2 :
							(strcasecmp("HYBRID", sub_node->val) == 0) ? 3 :
							0 /* BYPASS */);
					continue;
				} else {
					ConfNode *sub_node_val = NULL;
					char *val_fld[2];

						SCLogDebug(" sub_node (%s) ", sub_node->name);
					if (strcasecmp("input-output-map", sub_node->name) == 0) {

						TAILQ_FOREACH(sub_node_val, &sub_node->head, next) {
							SCLogDebug(" sub_node (%s) val (%s)", sub_node->name, sub_node_val->val);
							if (rte_strsplit(sub_node_val->val, sizeof(sub_node_val->val), val_fld, 2, '-') == 2) {
								SCLogDebug(" portmap: in %s out %s", val_fld[0], val_fld[1]);

								dpdk_config.portmap[inout_map_count][0] = atoi(val_fld[0]);
								dpdk_config.portmap[inout_map_count][1] = atoi(val_fld[1]);

								SCLogNotice(" in %u out %u ", dpdk_config.portmap[inout_map_count][0], dpdk_config.portmap[inout_map_count][1]);

								inout_map_count += 1;
							}
						}

						continue;
					}
				}
			}
		}
	}

	SCLogDebug(" dpdk_config: \n - pre_acl (%u)\n - post_acl (%u)\n - rx_reassemble (%d)\n - tx_fragment (%u)\n - mode (%u)",
			dpdk_config.pre_acl, dpdk_config.post_acl,
			dpdk_config.rx_reassemble, dpdk_config.tx_fragment,
			dpdk_config.mode);
	for (int j = 0; j < inout_map_count; j++) {
		SCLogDebug(" - port-map (%d), in (%d) out (%d)", j, dpdk_config.portmap[j][0], dpdk_config.portmap[j][1]);
	}
#endif

	SCReturnInt(ret);
}

void *ParseDpdkConfig(const char *dpdkCfg)
{
	SCEnter();
	struct rte_cfgfile *file = NULL;

#ifdef HAVE_DPDK
	file = rte_cfgfile_load(dpdkCfg, 0);

	/* get section name EAL */
	if (rte_cfgfile_has_section(file, "EAL")) {
		SCLogDebug(" section (EAL); count %d", rte_cfgfile_num_sections(file, "EAL", sizeof("EAL") - 1));
		SCLogDebug(" section (EAL) has entries %d", rte_cfgfile_section_num_entries(file, "EAL"));

		int n_entries = rte_cfgfile_section_num_entries(file, "EAL");
		struct rte_cfgfile_entry entries[n_entries];

		if (rte_cfgfile_section_entries(file, "EAL", entries, n_entries) != -1) {
			argument_count += n_entries * 2;
			SCLogDebug(" argument_count %d", argument_count);

			for (int i = 0; i < n_entries; i++) {
				SCLogDebug(" - entries[i].name: (%s) entries[i].value: (%s)", entries[i].name, entries[i].value);
				snprintf(argument[i * 2 + 1], 32, "%s", entries[i].name);
				snprintf(argument[i * 2 + 2], 32, "%s", entries[i].value);
				SCLogDebug(" - argument: (%s) (%s)", argument[i * 2 + 1], argument[i * 2 + 2]);
			}
		}
	}

	/* get section name PORT-X */
	for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
		char port_section_name[15] = {""};

		sprintf(port_section_name, "%s%d", "PORT-", i);
		if (rte_cfgfile_has_section(file, port_section_name)) {
			int n_port_entries = rte_cfgfile_section_num_entries(file, port_section_name);

			SCLogDebug(" %s", port_section_name);
			SCLogDebug(" section (PORT) has %d entries", n_port_entries);

			struct rte_cfgfile_entry entries[n_port_entries];
			if (rte_cfgfile_section_entries(file, port_section_name, entries, n_port_entries) != -1) {

				for (int j = 0; j < n_port_entries; j++) {
					SCLogDebug(" %s name: (%s) value: (%s)", port_section_name, entries[j].name, entries[j].value);

					if (strcasecmp("rx-queues", entries[j].name) == 0)
						dpdk_ports[i].rxq_count = atoi(entries[j].value);
					else if (strcasecmp("tx-queues", entries[j].name) == 0)
						dpdk_ports[i].txq_count = atoi(entries[j].value);
					else if (strcasecmp("mtu", entries[j].name) == 0)
						dpdk_ports[i].mtu = atoi(entries[j].value);
					else if (strcasecmp("rss-tuple", entries[j].name) == 0)
						dpdk_ports[i].rss_tuple = atoi(entries[j].value);
					else if (strcasecmp("jumbo", entries[j].name) == 0)
						dpdk_ports[i].jumbo = (strcasecmp(entries[j].value, "yes") == 0) ? 1 : 0;
					else if (strcasecmp("core", entries[j].name) == 0) {
						int lcoreindex = atoi(entries[j].value);
						SCLogNotice(" - lcore index is %d, rte_lcore_count %d ", lcoreindex, rte_lcore_count());
						dpdk_config.lcore_index_map[rte_lcore_count() % 64] |= 1 << lcoreindex;
					}
				}
			}
		}
	}

	/* get section name MEMPOOL-PORT */
	if (rte_cfgfile_has_section(file, "MEMPOOL-PORT")) {
		SCLogDebug(" section (MEMPOOL-PORT); count %d", rte_cfgfile_num_sections(file, "MEMPOOL-PORT", sizeof("MEMPOOL-PORT") - 1));
		SCLogDebug(" section (MEMPOOL-PORT) has entries %d", rte_cfgfile_section_num_entries(file, "MEMPOOL-PORT"));

		int n_entries = rte_cfgfile_section_num_entries(file, "MEMPOOL-PORT");
		struct rte_cfgfile_entry entries[n_entries];

		if (rte_cfgfile_section_entries(file, "MEMPOOL-PORT", entries, n_entries) != -1) {
			for (int j = 0; j < n_entries; j++) {
				SCLogDebug(" - entries[i] name: (%s) value: (%s)", entries[j].name, entries[j].value);

				if (strcasecmp("name", entries[j].name) == 0)
					rte_memcpy(dpdk_mempool_config.name, entries[j].value, sizeof(entries[j].value));
				if (strcasecmp("n", entries[j].name) == 0)
					dpdk_mempool_config.n = atoi(entries[j].value);
				if (strcasecmp("elt_size", entries[j].name) == 0)
					dpdk_mempool_config.elt_size = atoi(entries[j].value);
				if (strcasecmp("private_data_size", entries[j].name) == 0)
					dpdk_mempool_config.private_data_size = atoi(entries[j].value);
				if (strcasecmp("socket_id", entries[j].name) == 0)
					dpdk_mempool_config.private_data_size = atoi(entries[j].value);
			}
		}
	}

/* get section name ACL-IPV4 */
if (rte_cfgfile_has_section(file, "ACL-IPV4")) {
	int n_entries = rte_cfgfile_section_num_entries(file, "ACL-IPV4");
	struct rte_cfgfile_entry entries[n_entries];

	SCLogDebug(" section Name: ACL-IPv4 with entries %d", n_entries);
	if (rte_cfgfile_section_entries(file, "ACL-IPV4", entries, n_entries) != -1) {
		for (int j = 0; j < n_entries; j++) {
			SCLogDebug(" - entries[i] name (%s) val (%s)", entries[j].name, entries[j].value);
			if (strcasecmp("rule_count", entries[j].name) == 0)
				dpdk_acl_config.acl4_rules = atoi(entries[j].value);
		}
	}
}

/* get section name ACL-IPV6 */
if (rte_cfgfile_has_section(file, "ACL-IPV6")) {
	int n_entries = rte_cfgfile_section_num_entries(file, "ACL-IPV6");
	struct rte_cfgfile_entry entries[n_entries];

	SCLogDebug(" section Name: ACL-IPv6 with entries %d", n_entries);
	if (rte_cfgfile_section_entries(file, "ACL-IPV6", entries, n_entries) != -1) {
		for (int j = 0; j < n_entries; j++) {
			SCLogDebug(" - entries[i] name (%s) val (%s)", entries[j].name, entries[j].value);
			if (strcasecmp("rule_count", entries[j].name) == 0)
				dpdk_acl_config.acl6_rules = atoi(entries[j].value);
		}
	}
}

	rte_cfgfile_close(file);
#else
	SCLogInfo(" not configured for ParseDpdkConfig");
#endif

	SCReturnPtr(file, "void *");
}

static int DpdkGetThreadsCount(void *conf __attribute__((unused)))
{
	SCEnter();
	int ret = 0;

#ifdef HAVE_DPDK
	ret = rte_lcore_count();
#else
	SCLogInfo("\n ERROR: DPDK not supported!");
#endif

	SCReturnInt(ret);
}

static void *DpdkConfigParser(const char *device)
{
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	int ret = -1;
	static uint16_t port = 0;
	static uint16_t queue = 0;

	struct rte_eth_dev_info dev_info;

	char tname[50] = {""};
	ThreadVars *tv_worker = NULL;
	TmModule *tm_module = NULL;

	DpdkIfaceConfig_t *config = rte_zmalloc(NULL, sizeof(DpdkIfaceConfig_t), 0);
	if (config == NULL) {
		SCLogError(SC_ERR_DPDK_MEM, " failed to alloc memory");
		SCReturnPtr(NULL, "void *");
	}

	/* do I need this? */
	//(void) SC_ATOMIC_INIT(config->ref, 1);

	if (rte_eth_dev_info_get(port, &dev_info) != 0) {
		SCLogError(SC_ERR_DPDK_CONFIG, " failed to get DPDK port (%d) details", port);
		SCReturnPtr(NULL, "void *");
	}

	SCLogNotice(" port %u, rx queues %u", port, dev_info.nb_rx_queues);

	config->portid = port;
	config->queueid = queue;
	config->fwd_portid = dpdk_config.portmap[port][1];
	config->fwd_queueid = queue;

	SCLogNotice(" ----- port %u queue %u", port, queue);
	if ((queue + 1) < dev_info.nb_rx_queues) {
		queue += 1;
	} else {
		port += 1;
		queue = 0;
	}

	config->cluster_id = 1;
	config->cluster_type = PACKET_FANOUT_HASH;
	//config->cluster_type = PACKET_FANOUT_CPU;

	snprintf(config->in_iface, DPDK_ETH_NAME_SIZE, "unknown-in-%u", config->portid);
	ret = rte_eth_dev_get_name_by_port(config->portid, config->in_iface);
	snprintf(config->out_iface, DPDK_ETH_NAME_SIZE, "unknown-out-%u", config->fwd_portid);
	ret = rte_eth_dev_get_name_by_port(config->fwd_portid, config->out_iface);

	config->promiscous = 1;
	config->checksumMode =
		(dev_info.default_rxconf.offloads & DEV_RX_OFFLOAD_CHECKSUM) ?
		CHECKSUM_VALIDATION_RXONLY : CHECKSUM_VALIDATION_DISABLE;
	config->bpfFilter = NULL;

	config->flags = 0; /* what should be flags here? */
	config->copy_mode = 0; /* need to check from suricata IPS/IDS/BYPASS */

	SCLogNotice(" in (%s, %u, %u) out (%s, %u, %u) checksum %x",
		config->in_iface, config->portid, config->queueid,
		config->out_iface, config->fwd_portid, config->fwd_queueid,
		config->checksumMode);

 	/* do I need this? */
	//(void) SC_ATOMIC_ADD(config->ref, 1);
	return config;

#endif

	SCReturnPtr(NULL, "void *");
}

int RunModeDpdkWorkers(void)
{
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	int ret = -1;
	uint16_t rx_threads = DpdkGetRxThreads();
	char tname[50] = {""};
	ThreadVars *tv_worker = NULL;
	TmModule *tm_module = NULL;

	RunModeInitialize();
	TimeModeSetLive();

	/* dump dpdk application configuration */
	DumpGlobalConfig();

	for (int i = 0; i < rx_threads; i++) {
		snprintf(tname, sizeof(tname), "%s%d", "DPDKRX-THREAD-", i);

		tv_worker = TmThreadCreatePacketHandler(tname,
				"packetpool", "packetpool",
				"packetpool", "packetpool",
				"pktacqloop");
		if (tv_worker == NULL) {
			SCLogError(SC_ERR_DPDK_CONFIG, " TmThreadsCreate failed for (%s)", tname);
			exit(EXIT_FAILURE);
		}

		/*
		 * check if we need to do special processing
		 * 1) HW offload flags
		 * 2) drop unknown & error packets
		 * 3) if frames fragement and re-assembly is set, sent for reassembly thread
		 * else
		 * 4) can we skip this thread as we can use rte_eal_remote_launch
		 */

		tm_module = TmModuleGetByName("ReceiveDPDK");
		if (tm_module == NULL) {
			SCLogError(SC_ERR_DPDK_CONFIG, " TmModuleGetByName failed for ReceiveDPDK");
			exit(EXIT_FAILURE);
		}
		void *recv_ptr = DpdkConfigParser(NULL);
		if (recv_ptr == NULL) {
			SCLogError(SC_ERR_DPDK_CONFIG, " failed to create Data for RECV thread");
			exit(EXIT_FAILURE);
		}

		TmSlotSetFuncAppend(tv_worker, tm_module, (void *)recv_ptr);

		/*
		 * If pre=acl is configured, use decode thread to process the frames.
		 */

		tm_module = TmModuleGetByName("DecodeDPDK");
		if (tm_module == NULL) {
			SCLogError(SC_ERR_DPDK_CONFIG, " TmModuleGetByName failed for DecodeDPDK");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		tm_module = TmModuleGetByName("FlowWorker");
		if (tm_module == NULL) {
			SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		tm_module = TmModuleGetByName("RespondReject");
		if (tm_module == NULL) {
			printf("ERROR: TmModuleGetByName for RespondReject failed");
			exit(EXIT_FAILURE);
		}
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

		TmThreadSetCPU(tv_worker, WORKER_CPU_SET);

		if (TmThreadSpawn(tv_worker) != TM_ECODE_OK) {
			printf("ERROR: TmThreadSpawn failed\n");
			exit(EXIT_FAILURE);
		}

		SCLogNotice(" ceated %s for count %d ", tname, i);
	}

	SCLogInfo("RunMode DPDK workers initialised");
#endif
	SCReturnInt(ret);
}

#if DPDK-AF_WORKER
	/* default run mode is worker */
	ret = RunModeSetLiveCaptureWorkers(
			DpdkConfigParser, DpdkGetThreadsCount,
			(const char *) "ReceiveDpdk",
			(const char *) "DecodeDpdk",
			(const char *)"DecodeDpdk", NULL);

	if (ret != 0) {
		SCLogError(SC_ERR_RUNMODE, "DPDK workers runmode failed to start");
		exit(EXIT_FAILURE);
	}
#endif


uint8_t GetRunMode(void)
{
	SCEnter();
#ifdef HAVE_DPDK
	return dpdk_config.mode;
#else
	return 0; /*BYPASS*/
#endif
}

int DpdkGetRxThreads(void)
{
	SCEnter();
	int ret = 0;

#ifdef HAVE_DPDK
	for (int i = 0; i < (1 + (RTE_MAX_LCORE / 64)); i++)
		ret += __builtin_popcountll(dpdk_config.lcore_index_map[i]);
	SCLogNotice(" cores required from mysuricata.cfg is (%d)", ret);

	ret = 0;
	uint16_t ports =  rte_eth_dev_count_avail();
	for (int i = 0; i < ports; i++) {
		struct rte_eth_dev_info dev_info;
		if (rte_eth_dev_info_get(i, &dev_info) == 0) {
			SCLogNotice(" port (%u) queues (%u)", i, dev_info.nb_rx_queues);
			ret += dev_info.nb_rx_queues;
		}
	}
	SCLogNotice(" cores required from RX-Q is (%d)", ret);
	/* get RX queues per port */
	
#else
	SCLogInfo("\n ERROR: DPDK not supported!");
#endif

	SCReturnInt(ret);
}

uint16_t GetDpdkPort(void)
{
	SCEnter();
	int ret = 0;

#ifdef HAVE_DPDK
	ret = rte_eth_dev_count_avail();
#else
	SCLogInfo("\n ERROR: DPDK not supported!");
#endif

	SCReturnInt(ret);
}

void ListDpdkConfig(void)
{
#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	uint16_t i, nb_ports = GetDpdkPort();

	SCLogDebug(" DPDK supported!");

	SCLogNotice(" -- MEMPOOL-PORT --");
	SCLogNotice(" - name (%s)", dpdk_mempool_config.name);
	SCLogNotice(" - number of elements (%u)", dpdk_mempool_config.n);
	SCLogNotice(" - size of elements (%u)", dpdk_mempool_config.elt_size);
	SCLogNotice(" - scoketid (%u)", dpdk_mempool_config.socket_id);
	SCLogNotice(" - private data size (%u)", dpdk_mempool_config.private_data_size);
	SCLogNotice(" - mbuf pool ptr (%p)", dpdk_mempool_config.mbuf_ptr);
	SCLogNotice(" ");

	for (i = 0; i < nb_ports; i++)
	{
		SCLogNotice(" -- PORT-%u --", i);
		SCLogNotice(" - rxq (%u)", dpdk_ports[i].rxq_count);
		SCLogNotice(" - txq (%u)", dpdk_ports[i].txq_count);
		SCLogNotice(" - mtu (%u)", dpdk_ports[i].mtu);
		SCLogNotice(" - rss (%u)", dpdk_ports[i].rss_tuple);
		SCLogNotice(" - jumbo (%u)", dpdk_ports[i].jumbo);
		SCLogNotice(" ");
	}

	SCLogNotice(" -- APP Config --");
	SCLogNotice(" - pre_acl (%u)", dpdk_config.pre_acl);
	SCLogNotice(" - post_acl (%u)", dpdk_config.post_acl);
	SCLogNotice(" - rx_reassemble (%u)", dpdk_config.rx_reassemble);
	SCLogNotice(" - tx_fragment (%u)", dpdk_config.tx_fragment);
	SCLogNotice(" - mode (%u)", dpdk_config.mode);
	SCLogNotice(" - Ring Created (%u)", dpdk_num_pipelines);
	SCLogNotice(" ");

#endif
}

void ListDpdkPorts(void)
{
	SCEnter();
#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	uint16_t nb_ports = 0, i = 0;

	SCLogDebug(" DPDK supported!");
	if (RTE_PROC_INVALID != rte_eal_process_type()) {
		nb_ports = rte_eth_dev_count_avail();

		SCLogNotice("--- DPDK Ports ---");
		SCLogDebug("Overall Ports: %d ", nb_ports);

		for (; i < nb_ports; i++) {
			uint16_t mtu;
			struct rte_eth_dev_info info;
			struct rte_eth_link link;

			SCLogNotice(" -- Port: %d", i);

			rte_eth_dev_info_get(i, &info);
			rte_eth_link_get(i, &link);

			if (rte_eth_dev_get_mtu(i, &mtu) == 0)
				SCLogNotice(" -- mtu: %u", mtu);

			SCLogNotice(" -- promiscuous: %s", rte_eth_promiscuous_get(i)?"yes":"no");

			SCLogNotice(" -- link info: speed %u, duplex %u, autoneg %u, status %u",
					link.link_speed, link.link_duplex,
					link.link_autoneg, link.link_status);

			SCLogNotice(" -- driver: %s", info.driver_name);
			SCLogNotice(" -- NUMA node: %d", rte_eth_dev_socket_id(i));
			SCLogNotice(" ");
		}
	}
#endif
	return;
}

void DumpGlobalConfig(void)
{
	SCEnter();
#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else

	SCLogNotice("----- Global DPDK Config -----");

	ListDpdkConfig();
	ListDpdkPorts();

	SCLogNotice("------------------------------");
#endif

	return;
}

#ifdef HAVE_DPDK
static uint16_t
dpdk_mbuf_ptype_fiter_nonip(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	int i = 0, j = 0;

	for (; i < nb_pkts; i++) {
		struct rte_mbuf *m = pkts[i];

		//rte_pktmbuf_dump(stdout, m, m->pkt_len);

		if (((m->packet_type & (RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4)) != (RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4)) ||
			((m->packet_type & (RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4)) != (RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6)) ) {
			rte_pktmbuf_free(m);
			continue;
		}

			pkts[j++] = pkts[i];
	}

	return j;
}

static uint16_t
dpdk_sw_fiter_nonip(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	int i = 0, j = 0;
	for (; i < nb_pkts; i++) {
		/* condition check */
		struct rte_mbuf *m = pkts[i];
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		if (unlikely((eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) || 
			(eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)))) {
			rte_pktmbuf_free(m);
			continue;
		} 

		pkts[j++] = pkts[i];
	}

	return j;
}
#endif
