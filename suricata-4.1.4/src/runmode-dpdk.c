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
#include "dpdk-include-common.h"

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
#define SUIRCATA_DPDK_MAXARGS 16

static DpdkMempool_t dpdk_mempool_config;
static DpdkConfig_t dpdk_config;
static DpdkPortConfig_t dpdk_ports[RTE_MAX_ETHPORTS];

/* Number of configured parallel pipelines. */
static int dpdk_num_pipelines;

static uint16_t inout_map_count = 0;
uint16_t argument_count = 1;
char argument[SUIRCATA_DPDK_MAXARGS][32] = {{"./dpdk-suricata"}, {""}};
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
				/* MEMPOOL_CACHE_SIZE*/ 256, (dpdk_mempool_config.private_data_size == 0)? sizeof(Packet):dpdk_mempool_config.private_data_size,
				RTE_MBUF_DEFAULT_BUF_SIZE, dpdk_mempool_config.socket_id);
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
					if (dpdk_config.portmap[j][0] != dpdk_config.portmap[j][1]) {
						SCLogError(SC_ERR_DPDK_CONFIG, " Mode (%u); port in (%u) out (%u) is different\n",
							dpdk_config.mode,  dpdk_config.portmap[j][0], dpdk_config.portmap[j][1]);
						return -1;
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
	if (dpdk_config.pre_acl)
		SCLogDebug(" PRE-ACL to create!");
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
#endif
	SCLogInfo("\n ERROR: DPDK not supported!");

	SCReturnInt(ret);
}

static void *DpdkConfigParser(const char *device)
{
	SCEnter();

#ifdef HAVE_DPDK
	SCLogNotice(" device (%s)", device);
#endif

	SCLogInfo("\n ERROR: DPDK not supported!");
	SCReturnPtr(NULL, "void *");
}

int RunModeDpdkWorkers(void)
{
	SCEnter();
	int ret = -1;

#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	char tname[50] = {""};
	ThreadVars *tv_worker = NULL;
	TmModule *tm_module = NULL;

	RunModeInitialize();
	TimeModeSetLive();

	/* dump dpdk application configuration */
	DumpGlobalConfig();

	for (int i = 0; i < DpdkGetRxThreads(); i++) {
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
		TmSlotSetFuncAppend(tv_worker, tm_module, NULL);

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


#if 0
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


#if 0
#endif

	SCLogInfo("RunMode DPDK workers initialised");
#endif
	SCReturnInt(ret);
}

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

