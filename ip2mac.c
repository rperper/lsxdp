/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"
#include "linux/bpf.h"
#include "ip2mac.h"

#include <ctype.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size);
/* see lsxdp.c for the real DEBUG_MESSAGE */
int debug_message(const char *format, ...);
#define DEBUG_MESSAGE debug_message

int ip2mac_init(int max)
{
    return bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
                          sizeof(ip2mac_data_t), max, 0/*BPF_F_MMAPABLE*/);
}

static int find_addr(__u32 addr, ip2mac_data_t *data)
{
    /* Theoretically SIOCGARP should work.  But it doesn't.  And the
     * /proc/net/arp table has what I need.  Good enough for now.
    struct arpreq areq;
    memset(&areq, 0, sizeof(areq));
    areq.arp_pa.sa_family = AF_INET;
    ((struct sockaddr_in *)areq.arp_pa.sa_data)->sin_addr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        int err = errno;
    	DEBUG_MESSAGE("Socket creation error: %s\n", strerror(err));
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xdp_set_sendable socket creation error: %s", strerror(err));
        return -1;
    }
    if (ioctl(s, SIOCGARP, &areq) < 0)
    {
        int err = errno;
        close(s);
    	DEBUG_MESSAGE("ioctl error: %s\n", strerror(err));
        snprintf(sock->m_xdp_prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "xdp_set_sendable ioctl error: %s", strerror(err));
        return -1;
    }
    close(s);
    DEBUG_MESSAGE("Hardware address: %02x:%02x:%02x:%02x:%02x:%02x flags: 0x%x, dev: %s\n",
                  ((unsigned char *)&areq.arp_ha.sa_data)[0],
                  ((unsigned char *)&areq.arp_ha.sa_data)[1],
                  ((unsigned char *)&areq.arp_ha.sa_data)[2],
                  ((unsigned char *)&areq.arp_ha.sa_data)[3],
                  ((unsigned char *)&areq.arp_ha.sa_data)[4],
                  ((unsigned char *)&areq.arp_ha.sa_data)[5],
                  areq.arp_flags,
                  areq.arp_dev);
    */
    FILE *fh = fopen("/proc/net/arp", "r");
    if (!fh)
    {
        int err = errno;
        DEBUG_MESSAGE("Can't open arp table file: %s\n", strerror(err));
        errno = err;
        return -1;
    }
    char line[256];
    int found = 0;
    char addr_str[80];
    unsigned char mac[6];
    snprintf(addr_str, sizeof(addr_str), "%u.%u.%u.%u",
             ((unsigned char *)&addr)[0],
             ((unsigned char *)&addr)[1],
             ((unsigned char *)&addr)[2],
             ((unsigned char *)&addr)[3]);
    while (fgets(line, sizeof(line), fh))
    {
        if (!strncmp(line, addr_str, strlen(addr_str)))
        {
            DEBUG_MESSAGE("Found address %s in line: %s", addr_str, line);
            char *colon = strchr(line, ':');
            char *hex_char = (colon - 2);
            int index = 0;
            int pos = 0;
            if (strlen(hex_char) > 18)
            {
                while ((index < 5 && hex_char[pos + 2] == ':') ||
                       (index == 5 && hex_char[pos + 2] == ' '))
                {
                    mac[index] = ((isdigit(hex_char[pos]) ? (hex_char[pos] - '0') : (hex_char[pos] - 'a' + 10)) * 16) +
                                 (isdigit(hex_char[pos + 1]) ? (hex_char[pos + 1] - '0') : (hex_char[pos + 1] - 'a' + 10));
                    ++index;
                    pos += 3;
                }
                if (index == 6)
                {
                    found = 1;
                    break;
                }
            }
        }
        DEBUG_MESSAGE("Skip line: %s", line);
    }
    fclose(fh);
    if (!found)
    {
        DEBUG_MESSAGE("Can't find IP address in table\n");
        errno = ENOENT;
        return -1;
    }
    memcpy(data->m_mac, mac, sizeof(data->m_mac));
    DEBUG_MESSAGE("Hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

int ip2mac_lookup(int fd, __u32 addr, ip2mac_data_t *data)
{
    if (!bpf_map_lookup_elem(fd, &addr, data))
        return 0;
    if (find_addr(addr, data))
        return -1;
    return bpf_map_update_elem(fd, &addr, data, BPF_ANY);
}

int ip2mac_done(int fd)
{
    close(fd);
}
