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
/* Number of configured parallel pipelines. */
int dpdk_num_pipelines;
#endif

/*
 * runmode support for dpdk
 */

static const char *dpdk_default_mode = "workers";

const char *RunModeDpdkGetDefaultMode(void)
{
    return dpdk_default_mode;
}

void RunModeDpdkRegister(void)
{
#ifdef HAVE_DPDK
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "workers",
                              "Workers dpdk mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeDpdkWorkers);
    dpdk_default_mode = "workers";
#endif

	return;
}

void *ParseDpdkConfig(const char *dpdkCfg)
{
#ifdef HAVE_DPDK
	struct rte_cfgfile *file = rte_cfgfile_load(dpdkCfg, 0);

	printf(" ParseDpdkConfig %p\n", file);

	return file;
#else
	printf(" not configured for ParseDpdkConfig\n");

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
	return rte_eth_dev_count_avail();
}

void ListDpdkPorts(void)
{
#ifndef HAVE_DPDK
	printf("\n DPDK not supported!");
#else
	uint16_t nb_ports = 0, i = 0;

	if (RTE_PROC_INVALID != rte_eal_process_type()) {
		nb_ports = rte_eth_dev_count_avail();

		printf("\n\n --- DPDK Ports ---");
		printf("\n  - Overall Ports: %d ", nb_ports);

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
