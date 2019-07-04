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

#ifdef HAVE_DPDK
#define SUIRCATA_DPDK_MAXARGS 16

DpdkConfig_t dpdk_config;
DpdkPortConfig_t dpdk_ports[RTE_MAX_ETHPORTS];

/* Number of configured parallel pipelines. */
int dpdk_num_pipelines;

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

int CreateDpdkReassemblyFragement(void)
{
	int ret = 0;
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK\n");
#else
	if (dpdk_config.rx_reassemble)
		SCLogDebug(" Reassembly enable!\n");
	else
		SCLogDebug(" Reassembly disable!\n");

	if (dpdk_config.tx_fragment)
		SCLogDebug(" Fragement enable!\n");
	else
		SCLogDebug(" Fragement disable!\n");
#endif

	return ret;

}

int CreateDpdkAcl(void)
{
	int ret = 0;
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK\n");
#else
	if (dpdk_config.pre_acl)
		SCLogDebug(" PRE-ACL to create!\n");
	else
		SCLogDebug(" PRE-ACL need not to create!\n");

	if (dpdk_config.post_acl)
		SCLogDebug(" POST-ACL to create!\n");
	else
		SCLogDebug(" POST-ACL need not to create!\n");
#endif

	return ret;
}

int ParseDpdkYaml(void)
{
	int ret = 0;
	static uint16_t inout_map_count = 0;

	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" not configured for DPDK\n");
#else
	SCLogDebug(" configured for Dpdk\n");

	const char dpdk_components[10][40] = {"pre-acl", "post-acl", "rx-reassemble", "tx-fragment", "mode", "input-output-map"};
	SCLogDebug(" elements in yaml for dpdk: %d\n", (int) RTE_DIM(dpdk_components));

	ConfNode *node = ConfGetNode("dpdk");
	if (node == NULL) {
		SCLogError(SC_ERR_DPDK_CONFIG, "Unable to find dpdk in yaml");
		return -SC_ERR_DPDK_CONFIG;
	}

	ConfNode *sub_node = NULL;

	TAILQ_FOREACH(sub_node, &node->head, next) {
		SCLogDebug(" sub_node (%s) node (%s)\n", sub_node->name, node->name);

		for (unsigned long int i = 0; i < RTE_DIM(dpdk_components); i++) {
			if (strcasecmp(dpdk_components[i], sub_node->name) == 0) {
				SCLogDebug(" sub_node (%s) val (%s)\n", sub_node->name, sub_node->val);

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
					dpdk_config.mode = ((strcasecmp("IDS", sub_node->val) == 0)? 0 : 
							((strcasecmp("IPS", sub_node->val) == 0) ? 1 : 
							((strcasecmp("HYBRID", sub_node->val) == 0) ? 2 : 3)));
					continue;
				} else {
					ConfNode *sub_node_val = NULL;
					char *val_fld[2];

						SCLogDebug(" sub_node (%s) \n", sub_node->name);
					if (strcasecmp("input-output-map", sub_node->name) == 0) {

						TAILQ_FOREACH(sub_node_val, &sub_node->head, next) {
							SCLogDebug(" sub_node (%s) val (%s)\n", sub_node->name, sub_node_val->val);
							if (rte_strsplit(sub_node_val->val, sizeof(sub_node_val->val), val_fld, 2, '-') == 2) {
								SCLogDebug(" portmap: in %s out %s\n", val_fld[0], val_fld[1]);

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

	SCLogDebug(" dpdk_config: \n - pre_acl (%u)\n - post_acl (%u)\n - rx_reassemble (%d)\n - tx_fragment (%u)\n - mode (%u)\n",
			dpdk_config.pre_acl, dpdk_config.post_acl,
			dpdk_config.rx_reassemble, dpdk_config.tx_fragment,
			dpdk_config.mode);
	for (int j = 0; j < inout_map_count; j++) {
		SCLogDebug(" - port-map (%d), in (%d) out (%d)\n", j, dpdk_config.portmap[j][0], dpdk_config.portmap[j][1]);
	}

#endif
	return ret;
}

void *ParseDpdkConfig(const char *dpdkCfg)
{
	SCEnter();
#ifdef HAVE_DPDK
	struct rte_cfgfile *file = NULL;

	file = rte_cfgfile_load(dpdkCfg, 0);

	/* get section name EAL */
	if (rte_cfgfile_has_section(file, "EAL")) {
		SCLogDebug(" section (EAL); count %d\n", rte_cfgfile_num_sections(file, "EAL", sizeof("EAL") - 1));
		SCLogDebug(" section (EAL) has entries %d\n", rte_cfgfile_section_num_entries(file, "EAL"));

		int n_entries = rte_cfgfile_section_num_entries(file, "EAL");
		struct rte_cfgfile_entry entries[n_entries];

		if (rte_cfgfile_section_entries(file, "EAL", entries, n_entries) != -1) {
			argument_count += n_entries * 2;
			SCLogDebug(" argument_count %d\n", argument_count);

			for (int i = 0; i < n_entries; i++) {
				SCLogDebug(" - entries[i].name: (%s) entries[i].value: (%s)\n", entries[i].name, entries[i].value);
				snprintf(argument[i * 2 + 1], 32, "%s", entries[i].name);
				snprintf(argument[i * 2 + 2], 32, "%s", entries[i].value);
				SCLogDebug(" - argument: (%s) (%s)\n", argument[i * 2 + 1], argument[i * 2 + 2]);
			}
		}
	}

	for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
		char port_section_name[15] = {"PORT-"};

		sprintf(port_section_name, "%s%d", port_section_name, i);
		if (rte_cfgfile_has_section(file, port_section_name)) {
			int n_port_entries = rte_cfgfile_section_num_entries(file, port_section_name);

			SCLogDebug(" %s\n", port_section_name);
			SCLogDebug(" section (PORT) has entries %d\n", n_port_entries);

			struct rte_cfgfile_entry entries[n_port_entries];
			if (rte_cfgfile_section_entries(file, port_section_name, entries, n_port_entries) != -1) {

				for (int j = 0; j < n_port_entries; j++) {
					SCLogDebug(" - name: (%s) value: (%s)\n", entries[j].name, entries[j].value);

					if (strcasecmp("rx-queues", entries[j].name) == 0)
						dpdk_ports[j].rxq_count = atoi(entries[j].value);
					else if (strcasecmp("tx-queues", entries[j].name) == 0)
						dpdk_ports[j].txq_count = atoi(entries[j].value);
					else if (strcasecmp("mtu", entries[j].name) == 0)
						dpdk_ports[j].mtu = atoi(entries[j].value);
					else if (strcasecmp("rss-tuple", entries[j].name) == 0)
						dpdk_ports[j].rss_tuple = atoi(entries[j].value);
					else if (strcasecmp("jumbo", entries[j].name) == 0)
						dpdk_ports[j].jumbo = atoi(entries[j].value);
				}
			}
		}
	}

	rte_cfgfile_close(file);

	return file;
#else
	SCLogInfo(" not configured for ParseDpdkConfig\n");
	return NULL;
#endif

}

/**
 * \brief RunModeTileMpipeWorkers set up to process all modules in each thread.
 *
 * \param iface pointer to the name of the interface from which we will
 *              fetch the packets
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
int RunModeDpdkWorkers(void)
{
#ifndef HAVE_DPDK
	return 0;
#else
	int nb_workers = 0;
	return nb_workers;
#endif
}

uint16_t GetDpdkPort(void)
{
	SCEnter();
#ifdef HAVE_DPDK
	return rte_eth_dev_count_avail();
#else
	return 0;
#endif
}

void ListDpdkPorts(void)
{
	SCEnter();
#ifndef HAVE_DPDK
	SCLogInfo("\n ERROR: DPDK not supported!");
#else
	uint16_t nb_ports = 0, i = 0;

	SCLogDebug("\n DPDK supported!");
	if (RTE_PROC_INVALID != rte_eal_process_type()) {
		nb_ports = rte_eth_dev_count_avail();

		SCLogInfo("\n\n --- DPDK Ports ---");
		SCLogInfo("\n  - Overall Ports: %d ", nb_ports);

		for (; i < nb_ports; i++) {
			uint16_t mtu;
			struct rte_eth_dev_info info;
			struct rte_eth_link link;

			printf("\n\n -- Port: %d", i);

			rte_eth_dev_info_get(i, &info);
			rte_eth_link_get(i, &link);

			if (rte_eth_dev_get_mtu(i, &mtu) == 0)
				printf("\n -- mtu: %u", mtu);

			printf("\n -- promiscuous: %s", rte_eth_promiscuous_get(i)?"yes":"no");

			printf("\n -- link info: speed %u, duplex %u, autoneg %u, status %u",
					link.link_speed, link.link_duplex,
					link.link_autoneg, link.link_status);

			printf("\n -- driver: %s", info.driver_name);
			printf("\n -- NUMA node: %d", rte_eth_dev_socket_id(i));

		}
	}
#endif

	printf("\n\n");
	return;
}
