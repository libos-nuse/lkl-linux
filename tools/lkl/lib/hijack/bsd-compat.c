/*
 * BSD related compatibility functions
 * Copyright (c) 2017 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 *
 */

#include <stdio.h>
#define __USE_GNU
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <netinet/in.h>
#include <errno.h>

#include <lkl.h>
#include <lkl_host.h>

#include "xlate.h"

static int is_lklfd(int fd)
{
	if (fd < LKL_FD_OFFSET)
		return 0;

	return 1;
}

static void *resolve_sym(const char *sym)
{
	void *resolv;

	resolv = dlsym(RTLD_NEXT, sym);
	if (!resolv) {
		fprintf(stderr, "dlsym fail %s (%s)\n", sym, dlerror());
		assert(0);
	}
	return resolv;
}

static int lkl_call(int nr, int args, ...)
{
	long params[6];
	va_list vl;
	int i;

	va_start(vl, args);
	for (i = 0; i < args; i++)
		params[i] = va_arg(vl, long);
	va_end(vl);

	return lkl_set_errno(lkl_syscall(nr, params));
}

#define HOST_CALL(name)				\
	static long (*host_##name)();			\
	static void __attribute__((constructor(101)))	\
	init2_host_##name(void)			\
	{						\
		host_##name = resolve_sym(#name);	\
	}

#define CHECK_HOST_CALL(name) do {			\
		if (!host_##name)				\
			host_##name = resolve_sym(#name);	\
	} while (0)

static struct lkl_sockaddr *bsd2linux_saddr(const struct sockaddr *bsd_addr,
					    u_char len,
					    struct lkl_sockaddr *lkl_addr)
{
	if (!bsd_addr || !lkl_addr)
		return NULL;

	lkl_addr->sa_family = bsd_addr->sa_family;

	/* XXX: need more complete mapping table */
	if (lkl_addr->sa_family == AF_INET6)
		lkl_addr->sa_family = LKL_AF_INET6;

	memcpy(&((struct lkl_sockaddr *)lkl_addr)->sa_data,
	       &bsd_addr->sa_data, len ? len : bsd_addr->sa_len);

	return lkl_addr;
}

static struct sockaddr *linux2bsd_saddr(struct lkl_sockaddr *lkl_addr,
					u_char len,
					struct sockaddr *bsd_addr)
{
	if (!bsd_addr || !lkl_addr)
		return NULL;

	bsd_addr->sa_len = len;
	bsd_addr->sa_family = lkl_addr->sa_family;
	memcpy(&bsd_addr->sa_data, &lkl_addr->sa_data, len);

	/* XXX: need more complete mapping table */
	if (bsd_addr->sa_family == LKL_AF_INET6)
		bsd_addr->sa_family = AF_INET6;

	return bsd_addr;
}

#define LINUX_CMSG_ALIGN_DELTA						\
	(LKL_CMSG_ALIGN(sizeof(struct lkl_cmsghdr)) - sizeof(struct cmsghdr))

static void linux2bsd_cmsg(struct lkl_user_msghdr *lkl_msghdr,
			   u_char len,
			   struct msghdr *bsd_msghdr)
{
	struct lkl_cmsghdr *l_cmsg;
	struct cmsghdr *b_cmsg;

	if (!bsd_msghdr || !lkl_msghdr)
		return;

	b_cmsg = CMSG_FIRSTHDR(bsd_msghdr);
	for (l_cmsg = LKL_CMSG_FIRSTHDR(lkl_msghdr); l_cmsg != NULL;
	     l_cmsg = __LKL__CMSG_NXTHDR(lkl_msghdr->msg_control,
					 lkl_msghdr->msg_controllen,
					 l_cmsg)) {

		b_cmsg->cmsg_len = l_cmsg->cmsg_len;
		b_cmsg->cmsg_level = l_cmsg->cmsg_level;
		b_cmsg->cmsg_type = l_cmsg->cmsg_type;

		if (b_cmsg->cmsg_type == LKL_IPV6_HOPLIMIT)
			b_cmsg->cmsg_type = IPV6_HOPLIMIT;
		if (b_cmsg->cmsg_type == LKL_IPV6_PKTINFO)
			b_cmsg->cmsg_type = IPV6_PKTINFO;

		memcpy(CMSG_DATA(b_cmsg), LKL_CMSG_DATA(l_cmsg),
		       b_cmsg->cmsg_len - sizeof(struct cmsghdr));
		b_cmsg = CMSG_NXTHDR(bsd_msghdr, b_cmsg);
	}
}

HOST_CALL(sendto);
ssize_t sendto(int s, const void *msg, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	CHECK_HOST_CALL(sendto);
	struct lkl_sockaddr_in6 lkl_addr;

	if (!is_lklfd(s))
		return host_sendto(s, msg, len, flags, to, tolen);

	return lkl_call(__lkl__NR_sendto, 6, s, msg, len, flags,
			bsd2linux_saddr(to, tolen,
					(struct lkl_sockaddr *)&lkl_addr),
			tolen);
}

HOST_CALL(connect);
int connect(int s, const struct sockaddr *to, socklen_t tolen)
{
	CHECK_HOST_CALL(connect);
	struct lkl_sockaddr_in6 lkl_addr;

	if (!is_lklfd(s))
		return host_connect(s, to, tolen);

	return lkl_call(__lkl__NR_connect, 3, s,
			bsd2linux_saddr(to, tolen,
					(struct lkl_sockaddr *)&lkl_addr),
			tolen);
}

HOST_CALL(bind);
int bind(int s, const struct sockaddr *to, socklen_t tolen)
{
	CHECK_HOST_CALL(bind);
	struct lkl_sockaddr_in6 lkl_addr;
	int ret;

	if (!is_lklfd(s))
		return host_bind(s, to, tolen);

	ret = lkl_call(__lkl__NR_bind, 3, s,
		       bsd2linux_saddr(to, tolen,
				       (struct lkl_sockaddr *)&lkl_addr),
		       tolen);
	return ret;
}

HOST_CALL(accept);
int accept(int s, struct sockaddr *to, socklen_t *tolen)
{
	CHECK_HOST_CALL(accept);
	struct lkl_sockaddr_in6 lkl_addr;
	int ret;

	if (!is_lklfd(s))
		return host_accept(s, to, tolen);

	ret = lkl_call(__lkl__NR_accept, 3, s, &lkl_addr, tolen);
	if (ret < 0) {
		fprintf(stderr, "lkl %s fail(%d)\n", __func__, ret);
		return -1;
	}

	to = linux2bsd_saddr((struct lkl_sockaddr *)&lkl_addr, *tolen, to);
	return ret;
}

HOST_CALL(getsockname);
int getsockname(int s, struct sockaddr *name,
		socklen_t *namelen)
{
	CHECK_HOST_CALL(getsockname);
	int ret;
	struct lkl_sockaddr_in6 lkl_name;

	if (!is_lklfd(s))
		return host_getsockname(s, name, namelen);

	ret = lkl_call(__lkl__NR_getsockname, 3, s, &lkl_name, namelen);
	if (ret < 0) {
		fprintf(stderr, "lkl %s fail(%d)\n", __func__, ret);
		return -1;
	}

	name = linux2bsd_saddr((struct lkl_sockaddr *)&lkl_name, *namelen,
			       name);
	return 0;
}

HOST_CALL(sendmsg);
ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
	CHECK_HOST_CALL(sendmsg);
	struct lkl_user_msghdr l_msg;
	struct lkl_sockaddr_in6 lkl_addr;

	if (!is_lklfd(s))
		return host_sendmsg(s, msg, flags);

	if (msg->msg_name)
		l_msg.msg_name =
			bsd2linux_saddr(msg->msg_name, 0,
					(struct lkl_sockaddr *)&lkl_addr);

	l_msg.msg_namelen = msg->msg_namelen;
	l_msg.msg_iov = (struct lkl_iovec *)msg->msg_iov;
	l_msg.msg_iovlen = msg->msg_iovlen;
	l_msg.msg_control = msg->msg_control;
	l_msg.msg_controllen = msg->msg_controllen;
	l_msg.msg_flags = msg->msg_flags;

	return lkl_call(__lkl__NR_sendmsg, 3, s, &l_msg, flags);
}

HOST_CALL(recvmsg);
ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	CHECK_HOST_CALL(recvmsg);
	struct lkl_user_msghdr l_msg;
	struct lkl_sockaddr_in6 lkl_addr;
	struct lkl_cmsghdr *cmsghdr;
	long ret;

	if (!is_lklfd(s))
		return host_recvmsg(s, msg, flags);

	if (msg->msg_name)
		l_msg.msg_name =
			bsd2linux_saddr(msg->msg_name, 0,
					(struct lkl_sockaddr *)&lkl_addr);

	l_msg.msg_namelen = msg->msg_namelen;
	l_msg.msg_iov = (struct lkl_iovec *)msg->msg_iov;
	l_msg.msg_iovlen = msg->msg_iovlen;

	cmsghdr = malloc(msg->msg_controllen);
	l_msg.msg_control = cmsghdr;
	l_msg.msg_controllen = msg->msg_controllen;
	l_msg.msg_flags = msg->msg_flags;

	ret = lkl_call(__lkl__NR_recvmsg, 3, s, &l_msg, flags);
	if (ret < 0) {
		lkl_set_errno(ret);
		return -1;
	}

	if (msg->msg_name) {
		linux2bsd_saddr((struct lkl_sockaddr *)l_msg.msg_name,
				l_msg.msg_namelen,
				msg->msg_name);
		msg->msg_namelen = l_msg.msg_namelen;
	}

	msg->msg_iovlen = l_msg.msg_iovlen;

	if (msg->msg_controllen) {
		linux2bsd_cmsg(&l_msg, l_msg.msg_controllen, msg);
		msg->msg_controllen = l_msg.msg_controllen;
	}

	msg->msg_flags = l_msg.msg_flags;

	return ret;
}

int cap_rights_limit(int fd, const cap_rights_t *rights)
{
	return ENOSYS;
}
