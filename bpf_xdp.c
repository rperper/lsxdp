#include "libbpf.h" /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include "bpf.h"

#include <linux/if_link.h> /* Need XDP flags */

#include "lsxdp.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int xdp_link_attach(xdp_prog_t *prog, int ifindex, __u32 xdp_flags,
                    int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}
	if (err < 0)
    {
		snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN, "ERR: "
                 "ifindex(%d) link set xdp fd failed (%d): %s\n",
                 ifindex, -err, strerror(-err));
        return -1;
	}
	return 0;
}

int xdp_link_detach(xdp_prog_t *prog, int ifindex, __u32 xdp_flags,
                    __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err)
    {
		snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "ERR: get link xdp id failed (err=%d): %s\n",
			     -err, strerror(-err));
		return -1;
	}

	if (!curr_prog_id)
		return 0;

	if (expected_prog_id && curr_prog_id != expected_prog_id)
    {
		snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
			     "Expected prog ID(%d) no match(%d), not removing",
			     expected_prog_id, curr_prog_id);
		return -1;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0)
    {
		snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
		         "ERR: %s() link set xdp failed (err=%d): %s\n",
			     __func__, err, strerror(-err));
		return -1;
	}

	return 0;
}

#define XDP_UNKNOWN	XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
	[XDP_UNKNOWN]	= "XDP_UNKNOWN",
};

const char *action2str(__u32 action)
{
    if (action < XDP_ACTION_MAX)
        return xdp_action_names[action];
    return NULL;
}

