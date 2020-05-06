/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"
#include "linux/bpf.h"
#include "ip2mac.h"

#include "linux/rtnetlink.h"

#include <ctype.h>

int bpf(int cmd, union bpf_attr *attr, unsigned int size);
#define BUFSIZE 8192

struct gw_info {
    int                         ifi;
    int                         get_addr;
    struct sockaddr_storage     ip;
    char                        mac[ETH_ALEN];
    int                         mac_found;
    int                         gw_found;
};

int send_req(int sock, char *buf, size_t nlseq, size_t req_type)
{
    struct nlmsghdr *nlmsg;

    DEBUG_MESSAGE("send_req %d!\n", req_type);
    memset(buf, 0, BUFSIZE);
    nlmsg = (struct nlmsghdr *)buf;

    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = req_type;
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlmsg->nlmsg_seq = nlseq++;
    nlmsg->nlmsg_pid = getpid();

    if (send(sock, buf, nlmsg->nlmsg_len, 0) < 0)
    {
        int err = errno;
        DEBUG_MESSAGE("ERROR in send of get_gw message: %s\n", strerror(err));
        errno = err;
        return -1;
    }
    return nlseq;
}

int read_res(int sock, char *buf, size_t nlseq)
{
    struct nlmsghdr *nlmsg;
    int len;
    size_t total_len = 0;

    do {
        len = recv(sock, buf, BUFSIZE - total_len, 0);

        if (len < 0)
        {
            int err = errno;
            DEBUG_MESSAGE("ERROR in recv of get_gw results: %s\n", strerror(err));
            errno = err;
            return -1;
        }
        nlmsg = (struct nlmsghdr *)buf;

        if (NLMSG_OK(nlmsg, len) == 0)
        {
            int err = errno;
            DEBUG_MESSAGE("ERROR netlink didn't return for the request: %s\n", strerror(err));
            errno = err;
            return -1;
        }
        if (nlmsg->nlmsg_type == NLMSG_ERROR)
        {
            int err = errno;
            DEBUG_MESSAGE("ERROR netlink didn't like the request: %s\n", strerror(err));
            errno = err;
            return -1;
        }
        if (nlmsg->nlmsg_type == NLMSG_DONE)
            break;

        buf += len;
        total_len += len;

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;

    } while (nlmsg->nlmsg_seq != nlseq || nlmsg->nlmsg_pid != getpid());

    return total_len;
}

void parse_route(struct nlmsghdr *nlmsg, void *gw)
{
    struct rtmsg *rtmsg;
    struct rtattr *attr;
    size_t len;
    struct gw_info *info;
    int ip_found = 0;
    struct sockaddr_storage sa;

    info = (struct gw_info *)gw;
    rtmsg = (struct rtmsg *)NLMSG_DATA(nlmsg);

    if (rtmsg->rtm_family != info->ip.ss_family ||
        rtmsg->rtm_table != RT_TABLE_MAIN)
    {
        //DEBUG_MESSAGE("Return early from parse_route\n"); Lots of reasons
        return;
    }
    attr = (struct rtattr *)RTM_RTA(rtmsg);
    len = RTM_PAYLOAD(nlmsg);

    memset(&sa, 0, sizeof(sa));
    sa.ss_family = info->ip.ss_family;
    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == RTA_OIF)
            DEBUG_MESSAGE("Type == OIF, Data == %d\n", *(int *)RTA_DATA(attr));
        if (attr->rta_type == RTA_OIF && *(int *)RTA_DATA(attr) != info->ifi)
        {
            DEBUG_MESSAGE("Skip route entry for output interface %d != %d\n",
                          *(int *)RTA_DATA(attr), info->ifi);
            return;
        }
        if (attr->rta_type != RTA_GATEWAY)
            continue;
        if (info->ip.ss_family == AF_INET)
            ((struct sockaddr_in *)&sa)->sin_addr.s_addr = *(uint32_t *)RTA_DATA(attr);
        else
        {
            DEBUG_MESSAGE("About to do IPv6 copy (1)\n");
            memcpy(&((struct sockaddr_in6 *)&sa)->sin6_addr,
                   RTA_DATA(attr), sizeof(struct in6_addr));
            DEBUG_MESSAGE("Did IPv6 copy (1)\n");
        }
        char str_ip[MAX_STR_SOCKADDR];
        DEBUG_MESSAGE("   Initial IP: %s\n",
                      str_sockaddr(&sa, str_ip, sizeof(str_ip)));
        ip_found = 1;
    }
    if (ip_found)
    {
        char str_ip[MAX_STR_SOCKADDR];
        memcpy(&info->ip, &sa, sizeof(info->ip));
        DEBUG_MESSAGE("Gateway IP: %s\n",
                      str_sockaddr(&info->ip, str_ip, sizeof(str_ip)));
        info->gw_found = 1;
    }
}

void parse_neigh(struct nlmsghdr *nlmsg, void *gw)
{
    struct ndmsg *ndmsg;
    struct rtattr *attr;
    size_t len;
    unsigned char mac[ETH_ALEN];
    int ip_found = 0;
    int matched = 0;
    struct gw_info *info;
    struct sockaddr_storage sa;
    char str_ip1[MAX_STR_SOCKADDR], str_ip2[MAX_STR_SOCKADDR];

    info = (struct gw_info *)gw;
    ndmsg = (struct ndmsg *)NLMSG_DATA(nlmsg);

    if (ndmsg->ndm_family != info->ip.ss_family)
        return;

    if (ndmsg->ndm_ifindex != info->ifi)
    {
        DEBUG_MESSAGE("Skip neighbor for bad if %d != %d\n",
                      ndmsg->ndm_ifindex, info->ifi);
        return;
    }
    DEBUG_MESSAGE("Good if, state: 0x%x\n", ndmsg->ndm_state);
    attr = (struct rtattr *)RTM_RTA(ndmsg);
    len = RTM_PAYLOAD(nlmsg);

    memset(&sa, 0, sizeof(sa));
    sa.ss_family = info->ip.ss_family;
    str_sockaddr(&info->ip, str_ip2, sizeof(str_ip2));
    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
    {
        if (attr->rta_type == NDA_LLADDR)
            memcpy(mac, RTA_DATA(attr), ETH_ALEN);

        if (attr->rta_type == NDA_DST)
        {
            ip_found = 1;
            if (info->ip.ss_family == AF_INET)
                ((struct sockaddr_in *)&sa)->sin_addr.s_addr = *(uint32_t *)RTA_DATA(attr);
            else
            {
                DEBUG_MESSAGE("About to do IPv6 copy\n");
                memcpy(&((struct sockaddr_in6 *)&sa)->sin6_addr.in6_u,
                       RTA_DATA(attr),
                       sizeof(((struct sockaddr_in6 *)&sa)->sin6_addr.in6_u));
                DEBUG_MESSAGE("Did IPv6 copy\n");
            }
            str_sockaddr(&sa, str_ip1, sizeof(str_ip1));
            if (!strcmp(str_ip1, str_ip2))
                matched = 1;
            DEBUG_MESSAGE("IP found: %s (matched: %s)\n", str_ip1,
                          matched ? "YES" : "NO");
        }
    }

    if (ip_found && matched)
    {
        memcpy(info->mac, mac, ETH_ALEN);
        DEBUG_MESSAGE("Mac found: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],
                      mac[1], mac[2], mac[3], mac[4], mac[5]);
        info->mac_found = 1;
    }
}

void parse_response(char *buf, size_t len, void (cb)(struct nlmsghdr *, void *),
                    void *arg)
{
    struct nlmsghdr *nlmsg;

    nlmsg = (struct nlmsghdr *)buf;

    for (; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len))
        cb(nlmsg, arg);
}

static int get_addr_gw(int get_addr, int ifi, const struct sockaddr_storage *addr,
                       unsigned char mac[])
{
    DEBUG_MESSAGE("get_addr_gw, addr: %s, if_index: %d\n",
                  get_addr ? "YES" : "NO", ifi);
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock == -1)
    {
        int err = errno;
        DEBUG_MESSAGE("ERROR in PF_NETLINK socket: %s\n", strerror(err));
        errno = err;
        return -1;
    }
    char buf[BUFSIZE];
    size_t nlseq = 0;
    size_t msg_len;
    struct gw_info gw;

    memset(&gw, 0, sizeof(gw));
    gw.get_addr = get_addr;
    gw.ifi = ifi;
    memcpy(&gw.ip, addr, sizeof(gw.ip));
    if (!get_addr)
    {
        nlseq = send_req(sock, buf, nlseq, RTM_GETROUTE);
        if (nlseq == -1)
        {
            int err = errno;
            close(sock);
            errno = err;
            return -1;
        }
        msg_len = read_res(sock, buf, nlseq);

        if (msg_len <= 0)
        {
            int err = errno;
            close(sock);
            errno = err;
            return -1;
        }
        parse_response(buf, msg_len, &parse_route, &gw);
        if (!gw.gw_found)
        {
            DEBUG_MESSAGE("Gateway not found\n");
            errno = ENOENT;
            return -1;
        }
    }
    nlseq = send_req(sock, buf, nlseq, RTM_GETNEIGH);
    if (nlseq == -1)
    {
        int err = errno;
        close(sock);
        errno = err;
        return -1;
    }

    msg_len = read_res(sock, buf, nlseq);

    if (msg_len <= 0)
    {
        int err = errno;
        close(sock);
        errno = err;
        return -1;
    }

    parse_response(buf, msg_len, &parse_neigh, &gw);
    memcpy(mac, gw.mac, 6);
    close(sock);

    if (!gw.mac_found)
    {
        DEBUG_MESSAGE("Mac not found\n");
        errno = ENOENT;
        return -1;
    }
    return 0;

}

int ip2mac_init(int max)
{
    return bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct sockaddr_storage),
                          sizeof(ip2mac_data_t), max, 0/*BPF_F_MMAPABLE*/);
}

int ip2mac_lookup(int fd, int ifi, const struct sockaddr_storage *addr,
                  ip2mac_data_t *data)
{
    if (!bpf_map_lookup_elem(fd, addr, data))
        return 0;
    if (get_addr_gw(1, ifi, addr, data->m_mac))
    {
        if (get_addr_gw(0, ifi, addr, data->m_mac))
            return -1;
    }
    return bpf_map_update_elem(fd, &addr, data, BPF_ANY);
}

int ip2mac_done(int fd)
{
    close(fd);
}


