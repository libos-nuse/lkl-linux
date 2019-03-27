#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio.h"

typedef uint8_t u8;
#include <raspi.h>


struct lkl_netdev_raspi {
	struct lkl_netdev dev;
	int	is_closed;
	uint8_t buffer[FRAME_BUFFER_SIZE];
};

static inline size_t min(size_t a, size_t b)
{
	return (a > b) ? b : a;
}

static inline void platform_sleep(void)
{
	typedef int64_t time_t;
	struct __platform_timespec { time_t tv_sec; long tv_nsec; };
	extern int __platform_clock_nanosleep(int clock_id, int flags,
					      const struct timespec *request,
					      struct timespec *remain);

	struct __platform_timespec sl = {0, 0};

	__platform_clock_nanosleep(3 /* == CLOCK_MONOTONIC */, 0, &sl, NULL);
}

static int net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
	struct lkl_netdev_raspi *nd_raspi =
		container_of(nd, struct lkl_netdev_raspi, dev);
	void *buffer = nd_raspi->buffer;
	int seg, sent = 0;

	for (seg = 0; seg < cnt; seg++) {
		void *data = iov[seg].iov_base;
		size_t len = iov[seg].iov_len;
		size_t remaining = FRAME_BUFFER_SIZE - sent;
		size_t to_send = min(remaining, len);

		if (remaining == 0)
			break;
		else if (len == 0)
			continue;

		memcpy(buffer + sent, iov[seg].iov_base, to_send);
		sent += to_send;
	}

	if (sent > 0) {
		int ok = cr_sendframe(buffer, sent);

		if (!ok) {
			sent = 0;
			return -1;
		}
	}
	return sent;
}

static int net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
	struct lkl_netdev_raspi *nd_raspi =
		container_of(nd, struct lkl_netdev_raspi, dev);
	void *buffer = nd_raspi->buffer;
	unsigned int size = 0;
	size_t seg, copied = 0;
	int ok;

	ok = cr_recvframe(buffer, &size);
	if (!ok)
		return -1;

	for (seg = 0; copied < size && seg < cnt; seg++) {
		size_t to_copy = min(size - copied, iov[seg].iov_len);

		memcpy(iov[seg].iov_base, buffer, to_copy);
		copied += to_copy;
	}

	return copied;
}

static int net_poll(struct lkl_netdev *nd)
{
	struct lkl_netdev_raspi *nd_raspi =
		container_of(nd, struct lkl_netdev_raspi, dev);

	if (nd_raspi->is_closed)
		return LKL_DEV_NET_POLL_HUP;

	// XXX: Necessary to avoid deadlocks
	platform_sleep();

	return LKL_DEV_NET_POLL_RX | LKL_DEV_NET_POLL_TX;
}

static void net_poll_hup(struct lkl_netdev *nd)
{
	struct lkl_netdev_raspi *nd_raspi =
		container_of(nd, struct lkl_netdev_raspi, dev);

	nd_raspi->is_closed = 1;
}

static void net_free(struct lkl_netdev *nd)
{
	struct lkl_netdev_raspi *nd_raspi =
		container_of(nd, struct lkl_netdev_raspi, dev);

	free(nd_raspi);
}

struct lkl_dev_net_ops raspi_net_ops = {
	.tx = net_tx,
	.rx = net_rx,
	.poll = net_poll,
	.poll_hup = net_poll_hup,
	.free = net_free
};

struct lkl_netdev *lkl_netdev_raspi_create(void)
{
	struct lkl_netdev_raspi *nd;

	nd = malloc(sizeof(*nd));
	if (!nd)
		return NULL;

	nd->is_closed = 0;
	nd->dev.ops = &raspi_net_ops;
	nd->dev.has_vnet_hdr = 0;
	return nd;
}
