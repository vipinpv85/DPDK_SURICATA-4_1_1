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
 * DPDK source support
 */

#ifndef __SOURCE_DPDK_H__
#define __SOURCE_DPDK_H__

#ifdef _SYS_QUEUE_H_
#undef _SYS_QUEUE_H_
#include <sys/queue.h>
#endif

#include "rte_eal.h"
#include "rte_launch.h"
#include "rte_malloc.h"
#include "rte_ethdev.h"
#include "rte_mbuf.h"

#define DPDK_ETH_NAME_SIZE 48

#define InitDpdkSuricata(a, b) rte_eal_init(a, (char **)b)
#define KillDpdkSuricata do {\
	rte_eal_mp_wait_lcore();\
	rte_eal_cleanup();\
}while (0);

#if 0
typedef int32_t (*launchPtr) (__attribute__((unused)) void *arg);
#endif

typedef struct DpdkIfaceConfig
{
	char in_iface[DPDK_ETH_NAME_SIZE];
	char out_iface[DPDK_ETH_NAME_SIZE];

	uint8_t mode;
	uint16_t portid;
	uint16_t queueid;
	uint16_t fwd_portid;
	uint16_t fwd_queueid;

	struct rte_eth_dev_tx_buffer *tx_buffer;

	/* ring size in number of packets */
	int ringSize;
	int ringBufferId;
	
	uint8_t checksumMode;
	uint8_t promiscous;
	
	/* cluster param */
	int cluster_id;
	int cluster_type;
	
	/* misc use flags including ring mode */
	int flags;
	int copy_mode;
	
	char *bpfFilter;
	char *outIface;
	
	//SC_ATOMIC_DECLARE(unsigned int, ref);
} DpdkIfaceConfig_t;

typedef struct DpdkPacketVars_s
{
	uint16_t inP;
	uint16_t inQ;
	uint16_t outP;
	uint16_t outQ;

	struct rte_mbuf *m;
	struct rte_eth_dev_tx_buffer *buffer;
} DpdkPacketVars;


void TmModuleReceiveDpdkRegister(void);
void TmModuleDecodeDpdkRegister(void);

#if 0
int PfringConfGetThreads(void);
void PfringLoadConfig(void);

int32_t launchDpdkFrameParser(void);
int32_t ReceiveDpdkPkts_IPS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IDS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_BYPASS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_10_100(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_1000(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_10000(__attribute__((unused)) void *arg);
#endif

#endif /* __SOURCE_DPDKINTEL_H__ */
