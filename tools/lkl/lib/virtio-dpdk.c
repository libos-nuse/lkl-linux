/*
 * Intel DPDK based virtual network interface feature for NUSE
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Ryo Nakamura <upa@wide.ad.jp>
 *         Hajime Tazaki <tazaki@sfc.wide.ad.jp>
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>


#undef st_atime
#undef st_mtime
#undef st_ctime
#include <lkl_host.h>

static const char *ealargs[] = {
	"nuse_vif_dpdk",
	"-c 1",
	"-n 1",
};

static const struct rte_eth_rxconf rxconf = {
	.rx_thresh		= {
		.pthresh	= 1,
		.hthresh	= 1,
		.wthresh	= 1,
	},
};

static const struct rte_eth_txconf txconf = {
	.tx_thresh		= {
		.pthresh	= 1,
		.hthresh	= 1,
		.wthresh	= 1,
	},
	.tx_rs_thresh		= 1,
};

#define MAX_PKT_BURST           16
#define MEMPOOL_CACHE_SZ        32
#define MAX_PACKET_SZ           2048
#define MBUF_NUM                512
#define MBUF_SIZ        \
	(MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NUMDESC         256
#define NUMQUEUE        1

static int portid;
struct nuse_vif_dpdk {
	int portid;
	struct rte_mempool *rxpool, *txpool;    /* rin buffer pool */
	char txpoolname[16], rxpoolname[16];
	/* burst receive context by rump dpdk code */
	struct rte_mbuf *rms[MAX_PKT_BURST];
	int npkts;
	int bufidx;
};

struct lkl_netdev_dpdk {
    struct nuse_vif_dpdk dpdk;
};

static int net_tx(struct lkl_netdev *nd, void *data, int len)
{
	void *pkt;
	struct rte_mbuf *rm;
	struct nuse_vif_dpdk *dpdk = &((struct lkl_netdev_dpdk *)nd)->dpdk;

	rm = rte_pktmbuf_alloc(dpdk->txpool);
	pkt = rte_pktmbuf_append(rm, len);
	memcpy(pkt, data, len);

	rte_eth_tx_burst(dpdk->portid, 0, &rm, 1);
	/* XXX: should be bursted !! */
}

static int net_rx(struct lkl_netdev *nd, void *data, int *len)
{
    struct nuse_vif_dpdk *dpdk = &((struct lkl_netdev_dpdk *)nd)->dpdk;

	while (dpdk->npkts > 0) {
		struct rte_mbuf *rm, *rm0;
		void *r_data;
		uint32_t r_size;

		rm0 = dpdk->rms[dpdk->bufidx];
		dpdk->npkts--;
		dpdk->bufidx++;

		for (rm = rm0; rm; rm = rm->next) {
			r_data = rte_pktmbuf_mtod(rm, void *);
			r_size = rte_pktmbuf_data_len(rm);
			/* XXX */
			memcpy(data, r_data, r_size);
		}
	}

	if (dpdk->npkts == 0) {
		dpdk->npkts = rte_eth_rx_burst(dpdk->portid, 0, dpdk->rms,
					       MAX_PKT_BURST);
		dpdk->bufidx = 0;
	}

	return 0;
}

static int net_poll(struct lkl_netdev *nd, int events)
{
	int ret = 0;

	if (events & LKL_DEV_NET_POLL_RX)
		ret |= LKL_DEV_NET_POLL_RX;
	if (events & LKL_DEV_NET_POLL_TX)
		ret |= LKL_DEV_NET_POLL_TX;

	return ret;
}

struct lkl_dev_net_ops dpdk_net_ops = {
	.tx = net_tx,
	.rx = net_rx,
	.poll = net_poll,
};

struct lkl_netdev *nuse_vif_dpdk_create(const char *ifname)
{
    struct lkl_netdev_dpdk *nd;
	int ret = 0;
	static int dpdk_init = 0;
	struct rte_eth_conf portconf;
	struct rte_eth_link link;
	struct nuse_vif_dpdk *dpdk;

	if (!dpdk_init) {
		ret = rte_eal_init(sizeof(ealargs) / sizeof(ealargs[0]),
				   (void *)(uintptr_t)ealargs);
		if (ret < 0)
			fprintf(stderr, "failed to initialize eal\n");

		ret = -EINVAL;

		ret = rte_eal_pci_probe();
		if (ret < 0)
			fprintf(stderr, "eal pci probe failed\n");

		dpdk_init = 1;
	}

    nd = malloc(sizeof(struct lkl_netdev_dpdk));
	dpdk = &nd->dpdk;
	dpdk->portid = portid++;
	snprintf(dpdk->txpoolname, 16, "%s%s", "tx", ifname);
	snprintf(dpdk->rxpoolname, 16, "%s%s", "rx", ifname);

	dpdk->txpool =
		rte_mempool_create(dpdk->txpoolname,
				   MBUF_NUM, MBUF_SIZ, MEMPOOL_CACHE_SZ,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL, 0, 0);

	if (dpdk->txpool == NULL)
		fprintf(stderr, "failed to allocate tx pool\n");


	dpdk->rxpool =
		rte_mempool_create(dpdk->rxpoolname, MBUF_NUM, MBUF_SIZ, 0,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL, 0, 0);

	if (dpdk->rxpool == NULL)
		fprintf(stderr, "failed to allocate rx pool\n");


	memset(&portconf, 0, sizeof(portconf));
	ret = rte_eth_dev_configure(dpdk->portid, NUMQUEUE, NUMQUEUE,
				    &portconf);
	if (ret < 0)
		fprintf(stderr, "failed to configure port\n");


	ret = rte_eth_rx_queue_setup(dpdk->portid, 0, NUMDESC, 0, &rxconf,
				     dpdk->rxpool);

	if (ret < 0)
		fprintf(stderr, "failed to setup rx queue\n");

	ret = rte_eth_tx_queue_setup(dpdk->portid, 0, NUMDESC, 0, &txconf);
	if (ret < 0)
		fprintf(stderr, "failed to setup tx queue\n");

	ret = rte_eth_dev_start(dpdk->portid);
	if (ret < 0)
		fprintf(stderr, "failed to start device\n");

	rte_eth_link_get(dpdk->portid, &link);
	if (!link.link_status)
		printf("interface state is down\n");

	/* should be promisc ? */
	rte_eth_promiscuous_enable(dpdk->portid);

    return (struct lkl_netdev *)nd;
}
