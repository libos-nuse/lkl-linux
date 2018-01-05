/*
 * (C) 2012 Luigi Rizzo - Universita` di Pisa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * glue code to build the netmap bsd code under linux.
 * Some of these tweaks are generic, some are specific for
 * character device drivers and network code/device drivers.
 */

#ifndef _BSD_GLUE_H
#define _BSD_GLUE_H

/* a set of headers used in netmap */
#include <linux/version.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
//#include <linux/log2.h>	// ilog2
#include <linux/etherdevice.h>	// eth_type_trans
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/virtio.h>	// virt_to_phys

#define printf(fmt, arg...)	printk(KERN_ERR fmt, ##arg)
#define KASSERT(a, b)		BUG_ON(!(a))

/* Type redefinitions. XXX check them */
typedef	void *			bus_dma_tag_t;
typedef	void *			bus_dmamap_t;
typedef	int			bus_size_t;
typedef	int			bus_dma_segment_t;
typedef void *			bus_addr_t;
#define vm_paddr_t		phys_addr_t
/* XXX the 'off_t' on Linux corresponds to a 'long' */
#define vm_offset_t		uint32_t
struct thread;

/* endianness macros/functions */
#define le16toh			le16_to_cpu
#define le32toh			le32_to_cpu
#define le64toh			le64_to_cpu
#define be64toh			be64_to_cpu
#define htole32			cpu_to_le32
#define htole64			cpu_to_le64

#include <linux/jiffies.h>
#define	time_second	(jiffies_to_msecs(jiffies) / 1000U )

#define bzero(a, len)		memset(a, 0, len)
#define bcopy(_s, _d, len) 	memcpy(_d, _s, len)


// XXX maybe implement it as a proper function somewhere
// it is important to set s->len before the copy.
#define	m_devget(_buf, _len, _ofs, _dev, _fn)	( {		\
	struct sk_buff *s = netdev_alloc_skb(_dev, _len);	\
	if (s) {						\
		s->len += _len;					\
		skb_copy_to_linear_data_offset(s, _ofs, _buf, _len);	\
		s->protocol = eth_type_trans(s, _dev);		\
	}							\
	s; } )

#define	mbuf			sk_buff
#define	m_nextpkt		next			// chain of mbufs
#define m_freem(m)		dev_kfree_skb_any(m)	// free a sk_buff

/*
 * m_copydata() copies from mbuf to buffer following the mbuf chain.
 * XXX check which linux equivalent we should use to follow fragmented
 * skbufs.
 */

//#define m_copydata(m, o, l, b)	skb_copy_bits(m, o, b, l)
#define m_copydata(m, o, l, b)	skb_copy_from_linear_data_offset(m, o, b, l)

/*
 * struct ifnet is remapped into struct net_device on linux.
 * ifnet has an if_softc field pointing to the device-specific struct
 * (adapter).
 * On linux the ifnet/net_device is at the beginning of the device-specific
 * structure, so a pointer to the first field of the ifnet works.
 * We don't use this in netmap, though.
 *
 *	if_xname	name		device name
 *	if_capabilities	flags		// XXX not used
 *	if_capenable	priv_flags
 *		we would use "features" but it is all taken.
 *		XXX check for conflict in flags use.
 *
 *	if_bridge	atalk_ptr	struct nm_bridge (only for VALE ports)
 *
 * In netmap we use if_pspare[0] to point to the netmap_adapter,
 * in linux we have no spares so we overload ax25_ptr, and the detection
 * for netmap-capable is some magic in the area pointed by that.
 */
#define WNA(_ifp)		(_ifp)->ax25_ptr

#define ifnet           	net_device      /* remap */
#define	if_xname		name		/* field ifnet-> net_device */
//#define	if_capabilities		flags		/* IFCAP_NETMAP */
#define	if_capenable		priv_flags	/* IFCAP_NETMAP */
#define	if_bridge		atalk_ptr	/* remap, only for VALE ports */
#define ifunit_ref(_x)		dev_get_by_name(&init_net, _x);
#define if_rele(ifp)		dev_put(ifp)
#define CURVNET_SET(x)
#define CURVNET_RESTORE(x)


/*
 * We use spin_lock_irqsave() because we use the lock in the
 * (hard) interrupt context.
 */
typedef struct {
        spinlock_t      sl;
        ulong           flags;
} safe_spinlock_t;

static inline void mtx_lock(safe_spinlock_t *m)
{
        spin_lock_irqsave(&(m->sl), m->flags);
}

static inline void mtx_unlock(safe_spinlock_t *m)
{
	ulong flags = ACCESS_ONCE(m->flags);
        spin_unlock_irqrestore(&(m->sl), flags);
}

#define mtx_init(a, b, c, d)	spin_lock_init(&((a)->sl))
#define mtx_destroy(a)		// XXX spin_lock_destroy(a)

/* use volatile to fix a probable compiler error on 2.6.25 */
#define malloc(_size, type, flags)                      \
        ({ volatile int _v = _size; kmalloc(_v, GFP_ATOMIC | __GFP_ZERO); })

#define free(a, t)	kfree(a)

// XXX do we need GPF_ZERO ?
// XXX do we need GFP_DMA for slots ?
// http://www.mjmwired.net/kernel/Documentation/DMA-API.txt

#define contigmalloc(sz, ty, flags, a, b, pgsz, c)		\
	(char *) __get_free_pages(GFP_ATOMIC |  __GFP_ZERO,	\
		    ilog2(roundup_pow_of_two((sz)/PAGE_SIZE)))
#define contigfree(va, sz, ty)	free_pages((unsigned long)va,	\
		    ilog2(roundup_pow_of_two(sz)/PAGE_SIZE))

#define vtophys		virt_to_phys

/*--- selrecord and friends ---*/
/* wake_up() or wake_up_interruptible() ? */
#define	selwakeuppri(sw, pri)	wake_up(sw)
#define selrecord(x, y)		poll_wait((struct file *)x, y, pwait)
#define knlist_destroy(x)	// XXX todo

/* we use tsleep/wakeup to sleep a bit. */
#define	tsleep(a, b, c, t)	msleep(10)	// XXX
#define	wakeup(sw)				// XXX double check
#define microtime		do_gettimeofday


/*
 * The following trick is to map a struct cdev into a struct miscdevice
 */
#define	cdev			miscdevice


/*
 * XXX to complete - the dmamap interface
 */
#define	BUS_DMA_NOWAIT	0
#define	bus_dmamap_load(_1, _2, _3, _4, _5, _6, _7)
#define	bus_dmamap_unload(_1, _2)

typedef int (d_mmap_t)(struct file *f, struct vm_area_struct *vma);
typedef unsigned int (d_poll_t)(struct file * file, struct poll_table_struct *pwait);

/*
 * make_dev will set an error and return the first argument.
 * This relies on the availability of the 'error' local variable.
 */
#define make_dev(_cdev, _zero, _uid, _gid, _perm, _name)	\
	({error = misc_register(_cdev);				\
	D("run mknod /dev/%s c %d %d # error %d",		\
	    (_cdev)->name, MISC_MAJOR, (_cdev)->minor, error);	\
	 _cdev; } )
#define destroy_dev(_cdev)	misc_deregister(_cdev)

/*--- sysctl API ----*/
/*
 * linux: sysctl are mapped into /sys/module/ipfw_mod parameters
 * windows: they are emulated via get/setsockopt
 */
#define CTLFLAG_RD              1
#define CTLFLAG_RW              2

struct sysctl_oid;
struct sysctl_req;


#define SYSCTL_DECL(_1)
#define SYSCTL_OID(_1, _2, _3, _4, _5, _6, _7, _8)
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define _SYSCTL_BASE(_name, _var, _ty, _perm)			\
		module_param_named(_name, *(_var), _ty,         \
			( (_perm) == CTLFLAG_RD) ? 0444: 0644 )

#define SYSCTL_PROC(_base, _oid, _name, _mode, _var, _val, _desc, _a, _b)

#define SYSCTL_INT(_base, _oid, _name, _mode, _var, _val, _desc)        \
        _SYSCTL_BASE(_name, _var, int, _mode)

#define SYSCTL_LONG(_base, _oid, _name, _mode, _var, _val, _desc)       \
        _SYSCTL_BASE(_name, _var, long, _mode)

#define SYSCTL_ULONG(_base, _oid, _name, _mode, _var, _val, _desc)      \
        _SYSCTL_BASE(_name, _var, ulong, _mode)

#define SYSCTL_UINT(_base, _oid, _name, _mode, _var, _val, _desc)       \
         _SYSCTL_BASE(_name, _var, uint, _mode)

#define TUNABLE_INT(_name, _ptr)

#define SYSCTL_VNET_PROC                SYSCTL_PROC
#define SYSCTL_VNET_INT                 SYSCTL_INT

#define SYSCTL_HANDLER_ARGS             \
        struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);

#endif /* _BSD_GLUE_H */
