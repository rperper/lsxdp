/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __IP2Mac__
#define __IP2Mac__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ip2mac_data_s
{
    unsigned char m_mac[MAC_LEN];
} ip2mac_data_t;

int ip2mac_init(int max);
int ip2mac_lookup(int fd, char *ifn, int ifi, __u32 addr, ip2mac_data_t *data);
int ip2mac_done(int fd);
#ifdef __cplusplus
}
#endif

#endif
