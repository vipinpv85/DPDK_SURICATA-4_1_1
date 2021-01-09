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
#ifndef __RUNMODE_DPDK_H__
#define __RUNMODE_DPDK_H__

typedef struct __attribute__((__packed__))
{
	char name[50];
	unsigned n;
	unsigned elt_size;
	int socket_id;
	uint16_t private_data_size;
	void *mbuf_ptr;
} DpdkMempool_t;

typedef struct __attribute__((__packed__))
{
	uint8_t rxq_count;
	uint8_t txq_count;
	uint16_t mtu;
	uint8_t tx_buffer:3;
	uint8_t rss_tuple:2;
	uint8_t jumbo:1;
	uint8_t resv:2;
	uint64_t tx_buff_drop;
} DpdkPortConfig_t;

typedef struct __attribute__((__packed__))
{
	uint32_t acl4_rules;
	uint32_t acl6_rules;
	uint32_t ipv4AclCount;
	uint32_t ipv6AclCount;

	void *ipv4AclCtx;
	void *ipv6AclCtx;
	void *ipv4AclRules;
	void *ipv6AclRules;
} DpdkAclConfig_t;


#ifndef RTE_MAX_ETHPORTS
#define RTE_MAX_ETHPORTS 1
#endif

#ifndef RTE_MAX_QUEUES_PER_PORT
#define RTE_MAX_QUEUES_PER_PORT 1
#endif

typedef struct __attribute__((__packed__))
{
	uint16_t pre_acl:1;
	uint16_t post_acl:1;
	uint16_t tx_fragment:1;
	uint16_t rx_reassemble:1;
	uint16_t mode:2;
	uint16_t portmap[RTE_MAX_ETHPORTS][2];
	void *port_ring[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];
} DpdkConfig_t;

const char *RunModeDpdkGetDefaultMode(void);
void RunModeDpdkRegister(void);
uint16_t GetDpdkPort(void);
void ListDpdkPorts(void);
int ParseDpdkYaml(void);
int CreateDpdkAcl(void);
int CreateDpdkReassemblyFragement(void);
int ValidateDpdkConfig(void);
uint8_t GetRunMode(void);

#endif  /* __RUNMODE_DPDK_H__ */
