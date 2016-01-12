#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#undef st_atime
#undef st_mtime
#undef st_ctime
#include <lkl_host.h>


static int net_tx(union lkl_netdev nd, void *data, int len)
{
	int ret;

	ret = write(nd.fd, data, len);
	if (ret <= 0 && errno == -EAGAIN)
		return -1;
	return 0;
}

static int net_rx(union lkl_netdev nd, void *data, int *len)
{
	int ret;

	ret = read(nd.fd, data, *len);
	if (ret <= 0)
		return -1;
	*len = ret;
	return 0;
}

static int net_poll(union lkl_netdev nd, int events)
{
	struct pollfd pfd = {
		.fd = nd.fd,
	};
	int ret = 0;

	if (events & LKL_DEV_NET_POLL_RX)
		pfd.events |= POLLIN;
	if (events & LKL_DEV_NET_POLL_TX)
		pfd.events |= POLLOUT;

	while (poll(&pfd, 1, -1) < 0 && errno == EINTR)
		;

	if (pfd.revents & (POLLHUP | POLLNVAL))
		return -1;

	if (pfd.revents & POLLIN)
		ret |= LKL_DEV_NET_POLL_RX;
	if (pfd.revents & POLLOUT)
		ret |= LKL_DEV_NET_POLL_TX;

	return ret;
}

struct lkl_dev_net_ops tap_net_ops = {
	.tx = net_tx,
	.rx = net_rx,
	.poll = net_poll,
};

union lkl_netdev nuse_vif_tap_create(const char *ifname)
{
	union lkl_netdev nd;
	int ret;

	struct ifreq ifr = {
		.ifr_flags = IFF_TAP | IFF_NO_PI,
	};

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	nd.fd = open("/dev/net/tun", O_RDWR|O_NONBLOCK);
	if (nd.fd < 0) {
		fprintf(stderr, "failed to open tap: %s\n", strerror(errno));
		return nd;
	}

	ret = ioctl(nd.fd, TUNSETIFF, &ifr);
	if (ret < 0) {
		fprintf(stderr, "failed to attach to %s: %s\n",
			ifr.ifr_name, strerror(errno));
		close(nd.fd);
		return nd;
	}

	return nd;
}
