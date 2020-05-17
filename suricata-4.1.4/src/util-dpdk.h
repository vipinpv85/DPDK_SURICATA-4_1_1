#ifndef __UTIL_DPDK_H__
#define __UTIL_DPDK_H__

int32_t addDpdkAcl4Rule(uint32_t srcIp, uint32_t srcIpMask, uint32_t dstIp, uint32_t dstIpMask, uint8_t proto);
int32_t addDpdkAcl6Rule(uint32_t srcIp[4], uint32_t srcIpMask[4], uint32_t dstIp[4], uint32_t dstIpMask[4], uint8_t proto);
int32_t addDpdkAcl4Build(void);
int32_t addDpdkAcl6Build(void);

#endif /* __UTIL_DPDK_H__ */
