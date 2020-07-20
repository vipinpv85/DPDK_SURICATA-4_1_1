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
 * DPDK ingress packet support.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "host.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-mem.h"
#include "util-profiling.h"
#include "tmqh-packetpool.h"
#include "pkt-var.h"

#ifdef HAVE_DPDK

#include "source-dpdk.h"

/** storage for mpipe device names */
typedef struct DpdkDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(DpdkDevice_) next;
} DpdkDevice;


/** private device list */
static TAILQ_HEAD(, DpdkDevice_) dpdk_devices =
    TAILQ_HEAD_INITIALIZER(dpdk_devices);

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct DpdkThreadVars_
{
	ChecksumValidationMode checksum_mode;

	ThreadVars *tv;
	TmSlot *slot;

	Packet *in_p;

	uint8_t mode;
	uint16_t portid;
	uint16_t queueid;
	uint16_t fwd_portid;
	uint16_t fwd_queueid;
	int flags;
	int copy_mode;
	uint8_t checksumMode;
	uint8_t promiscous;
	void *txbuffer;

	/* dpdk params */

	/** stats/counters */
	uint64_t pkts;
	uint64_t bytes;
	uint64_t errs;

	uint64_t emptyrx;
	uint64_t failtx;
	uint64_t ipv4frag;
	uint64_t ipv6frag;
	uint64_t ipv4;
	uint64_t ipv6;
	uint64_t acllkp_succ;
	uint64_t acllkp_fail;
	uint64_t acllkp_hit;
	uint64_t acllkp_miss;
	uint64_t err_recv;
	uint64_t err_decode;
} DpdkThreadVars;

TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveDpdkInit(ThreadVars *, void *, void **);
TmEcode ReceiveDpdkDeinit(ThreadVars *, void *);
void ReceiveDpdkThreadExitStats(ThreadVars *, void *);

TmEcode DecodeDpdkThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeDpdk(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
#endif
TmEcode NoDpdkSupportExit(ThreadVars *, const void *, void **);

/*
 * dpdk configuration.
 */

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoDpdkSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
	SCLogError(SC_ERR_DPDK_CONFIG,"Error creating thread %s: you do not have "
		"support for DPDK enabled, please recompile "
		"with --enable-dpdk", tv->name);
	exit(EXIT_FAILURE);
}

void TmModuleReceiveDpdkRegister (void)
{
	SCEnter();
#ifdef HAVE_DPDK
	SCLogDebug(" dpdk support");

	tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
	tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDpdkInit;
	tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDpdkLoop;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDpdkThreadExitStats;
	tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDpdkDeinit;
	tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
	tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
#else
	SCLogDebug(" no dpdk support");

	tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
	tmm_modules[TMM_RECEIVEDPDK].ThreadInit = NoDpdkSupportExit;
	tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = NULL;
	tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVEDPDK].cap_flags = 0;
	tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
#endif

	SCReturn;
}

void TmModuleDecodeDpdkRegister (void)
{
	SCEnter();
#ifdef HAVE_DPDK
	SCLogDebug(" dpdk support");

	tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
	tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDpdkThreadInit;
	tmm_modules[TMM_DECODEDPDK].Func = DecodeDpdk;
	tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDpdkThreadDeinit;
	tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
	tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
#else

	SCLogDebug(" no dpdk support");

	tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
	tmm_modules[TMM_DECODEDPDK].ThreadInit = NoDpdkSupportExit;
	tmm_modules[TMM_DECODEDPDK].Func = NULL;
	tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_DECODEDPDK].ThreadDeinit = NULL;
	tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
	tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;

#endif
	SCReturn;
}

#if HAVE_DPDK
void DpdkReleasePacket(Packet *p)
{
	SCLogDebug(" IDS action is to drop");
	struct rte_mbuf *m = (struct rte_mbuf *) p->dpdk_v.m;
	rte_pktmbuf_free(m);
}

void DpdkFowardPacket(Packet *p)
{
	struct rte_mbuf *m = (struct rte_mbuf *) p->dpdk_v.m;

	if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) {
		SCLogDebug(" IPS action is to drop");
		rte_pktmbuf_free(m);
		return;
	}

	SCLogDebug(" IPS action is to fwd from (%u:%u) to (%u:%u)", p->dpdk_v.inP, p->dpdk_v.inQ, p->dpdk_v.outP, p->dpdk_v.outQ);
	if (rte_eth_tx_burst(p->dpdk_v.outP, p->dpdk_v.outQ, &m, 1) != 1) {
		rte_pktmbuf_free(m);
	}
}

void DpdkBufferFowardPacket(Packet *p)
{
	struct rte_mbuf *m = (struct rte_mbuf *) p->dpdk_v.m;

	if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) {
		SCLogDebug(" IPS action is to drop");
		rte_pktmbuf_free(m);
		return;
	}

	SCLogDebug(" IPS action is to buffer fwd from (%u:%u) to (%u:%u)", p->dpdk_v.inP, p->dpdk_v.inQ, p->dpdk_v.outP, p->dpdk_v.outQ);
	rte_eth_tx_buffer(p->dpdk_v.outP, p->dpdk_v.outQ, p->dpdk_v.buffer, m);
}

static inline
Packet *DpdkProcessPacket(DpdkThreadVars *ptv, struct rte_mbuf *m)
{
	u_char *pkt = rte_pktmbuf_mtod(m, u_char *);
	Packet *p = (Packet *)(rte_mbuf_to_priv(m));

	PACKET_RECYCLE(p);
	PKT_SET_SRC(p, PKT_SRC_WIRE);

	ptv->bytes += m->pkt_len;
	ptv->pkts += 1;

	gettimeofday(&p->ts, NULL);
	
	p->datalink = LINKTYPE_ETHERNET;
	/* No need to check return value, since the only error is pkt == NULL which can't happen here. */
	PacketSetData(p, pkt, m->pkt_len);

	/* dpdk Intel sepcific details */
	p->dpdk_v.m = (void *) m;
	p->dpdk_v.inP = ptv->portid;
	p->dpdk_v.outP = ptv->fwd_portid;
	p->dpdk_v.inQ = ptv->queueid;
	p->dpdk_v.outQ = ptv->fwd_queueid;
	p->dpdk_v.buffer = ptv->txbuffer;
	/* BYPASS - 0, IDS - 1, IPS - 2*/
	p->ReleasePacket = (ptv->mode == 1) ? DpdkReleasePacket : (ptv->txbuffer) ? DpdkBufferFowardPacket : DpdkFowardPacket;

	/* we are enabling DPDK PMD to validatte checksum - HW NIC offlaods */
	p->flags |= ptv->checksumMode;

	return p;
}
#endif

TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot)
{
	SCEnter();
	SCLogDebug(" Loop to fetch and put packets");

	uint64_t last_packet_time = rte_get_tsc_cycles(), now = 0;

#if HAVE_DPDK
	DpdkThreadVars *ptv = (DpdkThreadVars *)data;
	TmSlot *s = (TmSlot *)slot;
	ptv->slot = s->slot_next;
	Packet *p = NULL;

	SCLogDebug(" running on %d core %d\n", (int)pthread_self(), sched_getcpu());

	if (unlikely(ptv == NULL)) {
		SCReturnInt(TM_ECODE_FAILED);
	}

	while(1) {
		if (unlikely(suricata_ctl_flags != 0)) {
			SCLogDebug(" Stopping port RX (%d) Queue (%d)", ptv->portid, ptv->queueid);
			if (rte_eth_dev_rx_queue_stop(ptv->portid, ptv->queueid) != 0)
				SCReturnInt(TM_ECODE_FAILED);

			break;
		}

		SCLogDebug("RX-TX in %d out %d\n", ptv->portid, ptv->fwd_portid);

		struct rte_mbuf *bufs[16];
		const uint16_t nb_rx = rte_eth_rx_burst(ptv->portid, ptv->queueid, bufs, 8);

		if (likely(ptv->mode != 0)) {
			if (likely(nb_rx)) {

				int i, ret;
				for (i = 0; i < 4 && i < nb_rx; i++) {
					rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
				}

				for (i = 0; i < (nb_rx - 4); i++) {
					rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 2], void *));
					p = DpdkProcessPacket(ptv, bufs[i]);

					ret = TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
					if (unlikely(ret != TM_ECODE_OK)) {
						ptv->failtx += (uint64_t)1;
						TmqhOutputPacketpool(ptv->tv, p);
						SCLogNotice(" failed TmThreadsSlotProcessPkt");
						SCReturnInt(TM_ECODE_FAILED);
					}
				}

				for (; i < nb_rx; i++) {
					p = DpdkProcessPacket(ptv, bufs[i]);

					ret = TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
					if (unlikely(ret != TM_ECODE_OK)) {
						ptv->failtx += (uint64_t)1;
						TmqhOutputPacketpool(ptv->tv, p);
						SCLogNotice(" failed TmThreadsSlotProcessPkt");
						SCReturnInt(TM_ECODE_FAILED);
					}
				}
			}
			else {
				ptv->emptyrx += (uint64_t)1;
				struct timespec tim, tim2;
				tim.tv_sec = 0;
				tim.tv_nsec = 100;
				nanosleep(&tim , &tim2);
			}

		}
	}

	SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveDpdkInit(ThreadVars *tv, void *initdata, void **data)
{
	SCEnter();

#if HAVE_DPDK
	if (initdata == NULL) {
		SCLogError(SC_ERR_DPDK_CONFIG, " init data is empty");
		SCReturnInt(TM_ECODE_FAILED);
	}

	DpdkThreadVars *ptv = rte_zmalloc(NULL, sizeof(DpdkThreadVars), 0);
	if (unlikely(ptv == NULL)) {
		SCLogError(SC_ERR_DPDK_MEM, "failed to alloc memory");
		SCReturnInt(TM_ECODE_FAILED);
	}

	ptv->tv = tv;
	*data = (void *)ptv;

	DpdkIfaceConfig_t *dpdkconf = (DpdkIfaceConfig_t *) initdata;

	ptv->mode = dpdkconf->mode;
	ptv->portid = dpdkconf->portid;
	ptv->fwd_portid = dpdkconf->fwd_portid;
	ptv->queueid = dpdkconf->queueid;
	ptv->fwd_queueid = dpdkconf->fwd_queueid;
	ptv->flags = dpdkconf->flags;
	ptv->copy_mode = dpdkconf->copy_mode;
	ptv->checksumMode = dpdkconf->checksumMode;
	ptv->promiscous = dpdkconf->promiscous;
	ptv->txbuffer = dpdkconf->tx_buffer;

	*data = (void *)ptv;
#endif

	SCLogDebug("completed thread initialization for dpdk receive\n");
	SCReturnInt(TM_ECODE_OK);
}


TmEcode ReceiveDpdkDeinit(ThreadVars *tv, void *data)
{
	SCEnter();
	DpdkThreadVars *ptv = (DpdkThreadVars *)data;

	if (ptv->txbuffer)
		rte_eth_tx_buffer_flush(ptv->fwd_portid, ptv->fwd_portid, ptv->txbuffer);

	/* stop RX queue */
	rte_free(data);
	data = NULL;
	SCReturnInt(TM_ECODE_OK);
}


void ReceiveDpdkThreadExitStats(ThreadVars *tv, void *data)
{
	SCEnter();

	DpdkThreadVars *ptv = (DpdkThreadVars *)data;
	SCLogNotice(" ----- stats from worker thread -----");
	SCLogNotice(" | worker (Port:Queue) IN %2u:%2u - OUT %2u:%2u", ptv->portid, ptv->queueid, ptv->fwd_portid, ptv->fwd_queueid);
	SCLogNotice(" | PKT count          | %20"PRIu64, ptv->pkts);
	SCLogNotice(" | PKT bytes          | %20"PRIu64, ptv->bytes);
	SCLogNotice(" | PKT error count    | %20"PRIu64, ptv->errs);
	SCLogNotice(" | PKT emptyrx        | %20"PRIu64, ptv->emptyrx);
	SCLogNotice(" | PKT failtx         | %20"PRIu64, ptv->failtx);
	SCLogNotice(" | IPV4 non-frag      | %20"PRIu64, ptv->ipv4);
	SCLogNotice(" | IPV6 non-frag      | %20"PRIu64, ptv->ipv6);
	SCLogNotice(" | IPV4 frag          | %20"PRIu64, ptv->ipv4frag);
	SCLogNotice(" | IPV6 frag          | %20"PRIu64, ptv->ipv6frag);
	SCLogNotice(" | ACL Lookup success | %20"PRIu64, ptv->acllkp_succ);
	SCLogNotice(" | ACL Lookup fail    | %20"PRIu64, ptv->acllkp_fail);
	SCLogNotice(" | ACL Lookup hit     | %20"PRIu64, ptv->acllkp_hit);
	SCLogNotice(" | ACL Lookup miss    | %20"PRIu64, ptv->acllkp_miss);
	SCLogNotice(" | ERR recv           | %20"PRIu64, ptv->err_recv);
	SCLogNotice(" | ERR decode         | %20"PRIu64, ptv->err_decode);
	SCLogNotice(" -----------------------------------");

	SCReturn;
}

TmEcode DecodeDpdkThreadInit(ThreadVars *tv, void *initdata, void **data)
{
	SCEnter();
	SCLogDebug(" inside decode thread");

#if HAVE_DPDK
	DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
#endif

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data)
{
	SCEnter();

#if HAVE_DPDK
	SCLogDebug(" inside DecodeDpdkThreadDeinit ");

	DpdkThreadVars *ptv = (DpdkThreadVars *)data;

	if (data != NULL)
		DecodeThreadVarsFree(tv, data);

	SCLogDebug(" freed data!");
#endif

	SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeDpdk(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, 
                    PacketQueue *postq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END) {
//        PacketPoolReturnPacket(p);
        return TM_ECODE_OK;
    }

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

	/* call the decoder */
	DecodeEthernet(tv, dtv, p, (uint8_t *) p->ext_pkt /*rte_pktmbuf_mtod(p->dpdk_v.m, uint8_t *)*/,
		 p->pktlen /*p->dpdk_v.m->pkt_len*/, pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

#endif // HAVE_DPDK
