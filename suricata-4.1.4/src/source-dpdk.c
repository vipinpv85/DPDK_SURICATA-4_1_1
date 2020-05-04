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
#include "runmode-tile.h"
#include "source-mpipe.h"
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

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

	/* dpdk params */
	uint16_t portQueuePairCount;
	uint64_t portQueuePair[RTE_MAX_ETHPORTS * RTE_MAX_QUEUES_PER_PORT];

    /** stats/counters */
	uint64_t count_emptyrx;
	uint64_t count_failtx;
	uint64_t count_ipv4frag;
	uint64_t count_ipv6frag;
	uint64_t count_ipv4;
	uint64_t count_ipv6;
	uint64_t count_acllkpsucc;
	uint64_t count_acllkpfail;
	uint64_t count_acllkphit;
	uint64_t count_acllkpmiss;
	uint64_t count_recverr;
	uint64_t count_decodeerr;
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

#ifdef HAVE_DPDK
void TmModuleReceiveDpdkRegister (void)
{
	SCEnter();
	SCLogDebug(" dpdk support");

	//SCLogNotice(" - pre_acl (%u)", dpdk_config.pre_acl);
	//SCLogNotice(" - post_acl (%u)", dpdk_config.post_acl);
	//SCLogNotice(" - rx_reassemble (%u)", dpdk_config.rx_reassemble);
	//SCLogNotice(" - tx_fragment (%u)", dpdk_config.tx_fragment);

	tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
	tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDpdkInit;
	tmm_modules[TMM_RECEIVEDPDK].Func = /*NULL*/ReceiveDpdkLoop;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDpdkLoop;
	tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDpdkThreadExitStats;
	tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDpdkDeinit;
	tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
	tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;

	SCReturn;
}
#else
void TmModuleReceiveDPDKRegister (void)
{
	SCEnter();
	SCLogDebug(" no dpdk support");

	tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
	tmm_modules[TMM_RECEIVEDPDK].ThreadInit = NoDpdkSupportExit;
	tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = NULL;
	tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVEDPDK].cap_flags = 0;
	tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;

	SCReturn;
}
#endif

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

/* Release Packet without sending. */
void DpdkReleasePacket(Packet *p)
{
    /* Use this thread's context to free the packet. */
}

/* Unconditionally send packet, then release packet buffer. */
void DpdkReleasePacketCopyTap(Packet *p)
{
}

/* Release Packet and send copy if action is not DROP. */
void DpdkReleasePacketCopyIPS(Packet *p)
{
    if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        /* Return packet buffer without sending the packet. */
        DpdkReleasePacket(p);
    } else {
        /* Send packet */
        DpdkReleasePacketCopyTap(p);
    }
}

static void SendNoOpPacket(ThreadVars *tv, TmSlot *slot)
{
    Packet *p = PacketPoolGetPacket();
    if (p == NULL) {
        return;
    }

    p->datalink = DLT_RAW;
    p->proto = IPPROTO_TCP;

    /* So that DecodeMpipe ignores is. */
    p->flags |= PKT_PSEUDO_STREAM_END;

    p->flow = NULL;

    TmThreadsSlotProcessPkt(tv, slot, p);
}

TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot)
{
	SCEnter();

	SCLogDebug(" Loop to fetch and put packets");

#if HAVE_DPDK
	DpdkThreadVars *ptv = (DpdkThreadVars *)data;
	TmSlot *s = (TmSlot *)slot;
	//ptv->slot = s->slot_next;
	Packet *p = NULL;
	int rank = tv->rank;
	int max_queued = 0;
	char *ctype;

	if (unlikely(ptv == NULL)) {
		while (1);
		SCLogDebug(" running %s on %d core %d\n", __func__, pthread_self(), sched_getcpu());
		SCReturnInt(TM_ECODE_OK);
	}

	SCLogNotice("RX-TX Intf Id in %d out %d\n", ptv->portQueuePair[0] & 0xffff, (ptv->portQueuePair[0] >> 32)&0xffff);

#if 0
    ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
    if (ConfGet("mpipe.checksum-checks", &ctype) == 1) {
        if (ConfValIsTrue(ctype)) {
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(ctype))  {
            ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, 
                       "Invalid value for checksum-check for mpipe");
        }
    }

    /* Open Ingress Queue for this worker thread. */
    MpipeReceiveOpenIqueue(rank);
    gxio_mpipe_iqueue_t* iqueue = thread_iqueue;
    int update_counter = 0;
    uint64_t last_packet_time = get_cycle_count();

    for (;;) {

        /* Check to see how many packets are available to process. */
        gxio_mpipe_idesc_t *idesc;
        int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
        if (likely(n > 0)) {
            int i;
            int m = min(n, 16);

            /* Prefetch the idescs (64 bytes each). */
            for (i = 0; i < m; i++) {
                __insn_prefetch(&idesc[i]);
            }
            if (unlikely(n > max_queued)) {
                StatsSetUI64(tv, ptv->max_mpipe_depth,
                                     (uint64_t)n);
                max_queued = n;
            }
            for (i = 0; i < m; i++, idesc++) {
                if (likely(!gxio_mpipe_idesc_has_error(idesc))) {
                    p = MpipeProcessPacket(ptv, idesc);
                    p->mpipe_v.rank = rank;
                    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                        TmqhOutputPacketpool(ptv->tv, p);
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                } else {
                    if (idesc->be) {
            if (unlikely(n > max_queued)) {
                StatsSetUI64(tv, ptv->max_mpipe_depth,
                                     (uint64_t)n);
                max_queued = n;
            }
            for (i = 0; i < m; i++, idesc++) {
                if (likely(!gxio_mpipe_idesc_has_error(idesc))) {
                    p = MpipeProcessPacket(ptv, idesc);
                    p->mpipe_v.rank = rank;
                    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                        TmqhOutputPacketpool(ptv->tv, p);
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                } else {
                    if (idesc->be) {
                        /* Buffer Error - No buffer available, so mPipe
                         * dropped the packet. */
                        StatsIncr(tv, XlateStack(ptv, idesc->stack_idx));
                    } else {
                        /* Bad packet. CRC error */
                        StatsIncr(tv, ptv->mpipe_drop);
                        gxio_mpipe_iqueue_drop(iqueue, idesc);
                    }
                    gxio_mpipe_iqueue_release(iqueue, idesc);
                }
            }
            /* Move forward M packets in ingress ring. */
            gxio_mpipe_iqueue_advance(iqueue, m);

            last_packet_time = get_cycle_count();
        }
        if (update_counter-- <= 0) {
            /* Only periodically update and check for termination. */
            StatsSyncCountersIfSignalled(tv);
            update_counter = 10000;

            if (suricata_ctl_flags != 0) {
              break;
            }

            // If no packet has been received for some period of time, process a NOP packet
            // just to make sure that pseudo packets from the Flow manager get processed.
            uint64_t now = get_cycle_count();
            if (now - last_packet_time > 100000000) {
                SendNoOpPacket(ptv->tv, ptv->slot);
                last_packet_time = now;
            }
        }
    }
#endif

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveDpdkInit(ThreadVars *tv, void *initdata, void **data)
{
	SCEnter();
	SCLogNotice(" Kick start threads \n");

#if HAVE_DPDK
	DpdkThreadVars *ptv = rte_zmalloc(NULL, sizeof(DpdkThreadVars), 0);
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);

	ptv->tv = tv;

#if 0
    int result;
    const char *link_name = (char *)initdata;

    *data = (void *)ptv;

    /* Initialize and configure mPIPE, which is only done by one core. */

    if (strcmp(link_name, "multi") == 0) {
        int nlive = LiveGetDeviceCount();
    } else {
        SCLogInfo("using single interface %s", (char *)initdata);
    }
#endif

#endif
	SCLogNotice("completed thread initialization for dpdk receive\n");
	SCReturnInt(TM_ECODE_OK);
}


TmEcode ReceiveDpdkDeinit(ThreadVars *tv, void *data)
{
	SCEnter();

#if 0
    if (strcmp(link_name, "multi") == 0) {
        int nlive = LiveGetDeviceCount();
    } else {
        SCLogInfo("using single interface %s", (char *)initdata);
    }
#endif

	SCLogNotice(" wait for DPDK threads using rte_eal_wait ");
	SCReturnInt(TM_ECODE_OK);
}


void ReceiveDpdkThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    SCReturn;
}

TmEcode DecodeDpdkThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
	SCLogNotice(" inside decode thread");

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
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeDpdk(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, 
                    PacketQueue *postq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

#if HAVE_DPDK
    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

int DpdkLiveRegisterDevice(char *dev)
{
    DpdkDevice *nd = SCMalloc(sizeof(DpdkDevice));
    if (unlikely(nd == NULL)) {
        return -1;
    }

    nd->dev = SCStrdup(dev);
    if (unlikely(nd->dev == NULL)) {
        SCFree(nd);
        return -1;
    }
    TAILQ_INSERT_TAIL(&dpdk_devices, nd, next);
#endif

    SCLogDebug("DPDK device \"%s\" registered.", dev);
    return 0;
}

#endif // HAVE_DPDK
