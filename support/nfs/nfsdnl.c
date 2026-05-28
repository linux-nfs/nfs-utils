/*
 * nfsdnl.c -- send nfsd generic netlink commands
 *
 * Helper shared by nfsdctl and exportfs.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nfslib.h"
#include "xlog.h"
#include "nfsdnl.h"

#ifdef USE_SYSTEM_NFSD_NETLINK_H
#include <linux/nfsd_netlink.h>
#else
#include "nfsd_netlink.h"
#endif

#define NFSDNL_BUFSIZE	(4096)

static int error_handler(struct sockaddr_nl *UNUSED(nla), struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *UNUSED(msg), void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *UNUSED(msg),
		       void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

/**
 * nfsd_nl_cmd_str - send an nfsd netlink command carrying a string attribute
 * @cmd:   NFSD_CMD_* command number
 * @attr:  NFSD_A_* attribute number
 * @value: NUL-terminated string value for the attribute
 *
 * Returns 0 on success or a negative errno on failure.
 */
int nfsd_nl_cmd_str(int cmd, int attr, const char *value)
{
	struct genlmsghdr *ghdr;
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int family;
	int ret;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;
	if (genl_connect(sock)) {
		ret = -ECONNREFUSED;
		goto out_sock;
	}
	nl_socket_set_buffer_size(sock, NFSDNL_BUFSIZE, NFSDNL_BUFSIZE);

	family = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (family < 0) {
		ret = family;
		goto out_sock;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		ret = -ENOMEM;
		goto out_sock;
	}
	if (!genlmsg_put(msg, 0, 0, family, 0, 0, 0, 0)) {
		ret = -ENOMEM;
		goto out_msg;
	}

	ghdr = nlmsg_data(nlmsg_hdr(msg));
	ghdr->cmd = (__u8)cmd;
	nla_put_string(msg, attr, value);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb) {
		ret = -ENOMEM;
		goto out_msg;
	}

	ret = nl_send_auto(sock, msg);
	if (ret < 0)
		goto out_cb;

	ret = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);

	while (ret > 0)
		nl_recvmsgs(sock, cb);

out_cb:
	nl_cb_put(cb);
out_msg:
	nlmsg_free(msg);
out_sock:
	nl_socket_free(sock);
	return ret;
}
