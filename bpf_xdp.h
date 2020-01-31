/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

int xdp_link_attach(xdp_prog_t *sock, int ifindex, __u32 xdp_flags,
                    int prog_fd);
int xdp_link_detach(xdp_prog_t *sock, int ifindex, __u32 xdp_flags,
                    __u32 expected_prog_id);

const char *action2str(__u32 action);


#endif /* __COMMON_USER_BPF_XDP_H */
