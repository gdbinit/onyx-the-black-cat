/*
 * ________                        
 * \_____  \   ____ ___.__.___  ___
 *  /   |   \ /    <   |  |\  \/  /
 * /    |    \   |  \___  | >    < 
 * \_______  /___|  / ____|/__/\_ \
 *         \/     \/\/           \/ 
 *                    The Black Cat
 *
 * Copyright (c) fG!, 2011, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * proc.h
 *
 * Copyright (c) 2004-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 *
 */

#ifndef onyx_proc_h
#define onyx_proc_h

#define __APPLE_API_UNSTABLE
#define SYSCTL_DEF_ENABLED
#define PROC_DEF_ENABLED
#define MACH_KERNEL_PRIVATE

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h> 
#include <sys/proc.h>
#include <sys/sysctl.h>

// we need this to complete the proc structure
// osfmk/i386/locks.h
struct lck_mtx_t {
	union {
		struct {
			volatile uintptr_t              lck_mtxd_owner;
			unsigned long                   lck_mtxd_ptr;
			volatile uint32_t               lck_mtxd_waiters:16,
		lck_mtxd_pri:8,
		lck_mtxd_ilocked:1,
		lck_mtxd_mlocked:1,
		lck_mtxd_promoted:1,
		lck_mtxd_spin:1,
		lck_mtxd_pad4:4;        /* padding */
#ifdef __x86_64__
			unsigned int                    lck_mtxd_pad;
#endif
		} lck_mtxd;
		struct {
			unsigned long                   lck_mtxi_tag;
			struct _lck_mtx_ext_            *lck_mtxi_ptr;
			unsigned long                   lck_mtxi_pad;
		} lck_mtxi;
	} lck_mtx_sw;
};

// osfmk/i386/locks.h
struct lck_spin_t {
	unsigned long   interlock;
	unsigned long   lck_spin_pad[9];        /* XXX - usimple_lock_data_t */
};



// ripped from xnu/bsd/sys/proc_internal.h
// Needed so we can access the proc structure passed to the syscall
// I had to comment some fields because other kernel includes would be needed
// This should be valid since we are not doing any copies of this structure (just having it's definition to avoid dereference pointer to incomplete types)
// else things might go wrong (big kabooommm)
// FOR SNOW LEOPARD
struct	proc {
	LIST_ENTRY(proc) p_list;		/* List of all processes. */
	
	pid_t		p_pid;			/* Process identifier. (static)*/
	void * 		task;			/* corresponding task (static)*/
	struct	proc *	p_pptr;		 	/* Pointer to parent process.(LL) */
	pid_t		p_ppid;			/* process's parent pid number */
	pid_t		p_pgrpid;		/* process group id of the process (LL)*/
	
	struct lck_mtx_t 	p_mlock;		/* mutex lock for proc */
	
	char		p_stat;			/* S* process status. (PL)*/
	char		p_shutdownstate;
	char		p_kdebug;		/* P_KDEBUG eq (CC)*/ 
	char		p_btrace;		/* P_BTRACE eq (CC)*/
	
	LIST_ENTRY(proc) p_pglist;		/* List of processes in pgrp.(PGL) */
	LIST_ENTRY(proc) p_sibling;		/* List of sibling processes. (LL)*/
	LIST_HEAD(, proc) p_children;		/* Pointer to list of children. (LL)*/
	TAILQ_HEAD( , uthread) p_uthlist; 	/* List of uthreads  (PL) */
	
	LIST_ENTRY(proc) p_hash;		/* Hash chain. (LL)*/
	TAILQ_HEAD( ,eventqelt) p_evlist;	/* (PL) */
	
	struct lck_mtx_t	p_fdmlock;		/* proc lock to protect fdesc */
	
	/* substructures: */
	kauth_cred_t	p_ucred;		/* Process owner's identity. (PL) */
	struct	filedesc *p_fd;			/* Ptr to open files structure. (PFDL) */
	struct	pstats *p_stats;		/* Accounting/statistics (PL). */
	struct	plimit *p_limit;		/* Process limits.(PL) */
	
	struct	sigacts *p_sigacts;		/* Signal actions, state (PL) */
	int		p_siglist;		/* signals captured back from threads */
	struct lck_spin_t	p_slock;		/* spin lock for itimer/profil protection */
	
#define	p_rlimit	p_limit->pl_rlimit
	
	struct	plimit *p_olimit;		/* old process limits  - not inherited by child  (PL) */
	unsigned int	p_flag;			/* P_* flags. (atomic bit ops) */
	unsigned int	p_lflag;		/* local flags  (PL) */
	unsigned int	p_listflag;		/* list flags (LL) */
	unsigned int	p_ladvflag;		/* local adv flags (atomic) */
	int		p_refcount;		/* number of outstanding users(LL) */
	int		p_childrencnt;		/* children holding ref on parent (LL) */
	int		p_parentref;		/* children lookup ref on parent (LL) */
	
	pid_t		p_oppid;	 	/* Save parent pid during ptrace. XXX */
	u_int		p_xstat;		/* Exit status for wait; also stop signal. */
	
#ifdef _PROC_HAS_SCHEDINFO_
	/* may need cleanup, not used */
	u_int		p_estcpu;	 	/* Time averaged value of p_cpticks.(used by aio and proc_comapre) */
	fixpt_t		p_pctcpu;	 	/* %cpu for this process during p_swtime (used by aio)*/
	u_int		p_slptime;		/* used by proc_compare */
#endif /* _PROC_HAS_SCHEDINFO_ */
	
	struct	itimerval p_realtimer;		/* Alarm timer. (PSL) */
	struct	timeval p_rtime;		/* Real time.(PSL)  */
	struct	itimerval p_vtimer_user;	/* Virtual timers.(PSL)  */
	struct	itimerval p_vtimer_prof;	/* (PSL) */
	
	struct	timeval	p_rlim_cpu;		/* Remaining rlim cpu value.(PSL) */
	int		p_debugger;		/*  NU 1: can exec set-bit programs if suser */
	boolean_t	sigwait;	/* indication to suspend (PL) */
	void	*sigwait_thread;	/* 'thread' holding sigwait(PL)  */
	void	*exit_thread;		/* Which thread is exiting(PL)  */
	int	p_vforkcnt;		/* number of outstanding vforks(PL)  */
	void *  p_vforkact;     	/* activation running this vfork proc)(static)  */
	int	p_fpdrainwait;		/* (PFDL) */
	pid_t	p_contproc;	/* last PID to send us a SIGCONT (PL) */
	
	/* Following fields are info from SIGCHLD (PL) */
	pid_t	si_pid;			/* (PL) */
	u_int   si_status;		/* (PL) */
	u_int	si_code;		/* (PL) */
	uid_t	si_uid;			/* (PL) */
	
	void * vm_shm;			/* (SYSV SHM Lock) for sysV shared memory */
	
#if CONFIG_DTRACE
	user_addr_t			p_dtrace_argv;			/* (write once, read only after that) */
	user_addr_t			p_dtrace_envp;			/* (write once, read only after that) */
	lck_mtx_t			p_dtrace_sprlock;		/* sun proc lock emulation */
	int				p_dtrace_probes;		/* (PL) are there probes for this proc? */
	u_int				p_dtrace_count;			/* (sprlock) number of DTrace tracepoints */
	struct dtrace_ptss_page*	p_dtrace_ptss_pages;		/* (sprlock) list of user ptss pages */
	struct dtrace_ptss_page_entry*	p_dtrace_ptss_free_list;	/* (atomic) list of individual ptss entries */
	struct dtrace_helpers*		p_dtrace_helpers;		/* (dtrace_lock) DTrace per-proc private */
	struct dof_ioctl_data*		p_dtrace_lazy_dofs;		/* (sprlock) unloaded dof_helper_t's */
#endif /* CONFIG_DTRACE */
	
	/* XXXXXXXXXXXXX BCOPY'ed on fork XXXXXXXXXXXXXXXX */
	/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_argslen
	
	u_int	p_argslen;	 /* Length of process arguments. */
	int  	p_argc;			/* saved argc for sysctl_procargs() */
	user_addr_t user_stack;		/* where user stack was allocated */
	struct	vnode *p_textvp;	/* Vnode of executable. */
	off_t	p_textoff;		/* offset in executable vnode */
	
	sigset_t p_sigmask;		/* DEPRECATED */
	sigset_t p_sigignore;	/* Signals being ignored. (PL) */
	sigset_t p_sigcatch;	/* Signals being caught by user.(PL)  */
	
	u_char	p_priority;	/* (NU) Process priority. */
	u_char	p_resv0;	/* (NU) User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value.(PL) */
	u_char	p_resv1;	/* (NU) User-priority based on p_cpu and p_nice. */
	
#if CONFIG_MACF
	int	p_mac_enforce;			/* MAC policy enforcement control */
#endif
	
	char	p_comm[MAXCOMLEN+1];
	char	p_name[(2*MAXCOMLEN)+1];	/* PL */
	
	struct 	pgrp *p_pgrp;	/* Pointer to process group. (LL) */
	int		p_iopol_disk;	/* disk I/O policy (PL) */
	uint32_t	p_csflags;	/* flags for codesign (PL) */
	uint32_t	p_pcaction;	/* action  for process control on starvation */
	uint8_t p_uuid[16];		/* from LC_UUID load command */
	
	/* End area that is copied on creation. */
	/* XXXXXXXXXXXXX End of BCOPY'ed on fork (AIOLOCK)XXXXXXXXXXXXXXXX */
#define	p_endcopy	p_aio_total_count
	int		p_aio_total_count;		/* all allocated AIO requests for this proc */
	int		p_aio_active_count;		/* all unfinished AIO requests for this proc */
	TAILQ_HEAD( , aio_workq_entry ) p_aio_activeq; 	/* active async IO requests */
	TAILQ_HEAD( , aio_workq_entry ) p_aio_doneq;	/* completed async IO requests */
	
	//	struct klist p_klist;  /* knote list (PL ?)*/
	
	struct	rusage *p_ru;	/* Exit information. (PL) */
	thread_t 	p_signalholder;
	thread_t 	p_transholder;
	
	/* DEPRECATE following field  */
	u_short	p_acflag;	/* Accounting flags. */
	
	struct lctx *p_lctx;		/* Pointer to login context. */
	LIST_ENTRY(proc) p_lclist;	/* List of processes in lctx. */
	user_addr_t 	p_threadstart;		/* pthread start fn */
	user_addr_t 	p_wqthread;		/* pthread workqueue fn */
	int 	p_pthsize;			/* pthread size */
	user_addr_t	p_targconc;		/* target concurrency ptr */
	void * 	p_wqptr;			/* workq ptr */
	int 	p_wqsize;			/* allocated size */
	boolean_t       p_wqiniting;            /* semaphore to serialze wq_open */
	//	lck_spin_t	p_wqlock;		/* lock to protect work queue */
	struct  timeval p_start;        	/* starting time */
	void *	p_rcall;
	int		p_ractive;
	int	p_idversion;		/* version of process identity */
	void *	p_pthhash;			/* pthread waitqueue hash */
#if DIAGNOSTIC
	unsigned int p_fdlock_pc[4];
	unsigned int p_fdunlock_pc[4];
#if SIGNAL_DEBUG
	unsigned int lockpc[8];
	unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
	uint64_t	p_dispatchqueue_offset;
};


// bsd/sys/proc.h
#define	P_TRACED	0x00000800
#define P_NOCLDSTOP     0x00000008      /* No SIGCHLD when children stop */
#define	P_LP64		0x00000004	/* Process is LP64 */

// bsd/sys/sysctl.h
struct _pcred {
	char	pc_lock[72];		/* opaque content */
	struct	ucred *pc_ucred;	/* Current credentials. */
	uid_t	p_ruid;			/* Real user id. */
	uid_t	p_svuid;		/* Saved effective user id. */
	gid_t	p_rgid;			/* Real group id. */
	gid_t	p_svgid;		/* Saved effective group id. */
	int	p_refcnt;		/* Number of references. */
};

// bsd/sys/sysctl.h
struct _ucred {
	int32_t	cr_ref;			/* reference count */
	uid_t	cr_uid;			/* effective user id */
	short	cr_ngroups;		/* number of groups */
	gid_t	cr_groups[NGROUPS];	/* groups */
};

/* Exported fields for kern sysctls */
// bsd/sys/proc_internal.h
struct extern_proc {
	union {
		struct {
			struct	proc *__p_forw;	/* Doubly-linked run/sleep queue. */
			struct	proc *__p_back;
		} p_st1;
		struct timeval __p_starttime; 	/* process start time */
	} p_un;
#define p_forw p_un.p_st1.__p_forw
#define p_back p_un.p_st1.__p_back
#define p_starttime p_un.__p_starttime
	struct	vmspace *p_vmspace;	/* Address space. */
	// bsd/sys/signalvar.h
	struct	sigacts *p_sigacts;	/* Signal actions, state (PROC ONLY). */
	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	pid_t	p_pid;			/* Process identifier. */
	pid_t	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	caddr_t user_stack;	/* where user stack was allocated */
	void	*exit_thread;	/* XXX Which thread is exiting? */
	int		p_debugger;		/* allow to debug */
	boolean_t	sigwait;	/* indication to suspend */
	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */
	struct	itimerval p_realtimer;	/* Alarm timer. */
	struct	timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */
	int	p_traceflag;		/* Kernel trace points. */
	struct	vnode *p_tracep;	/* Trace to vnode. */
	int	p_siglist;		/* DEPRECATED. */
	struct	vnode *p_textvp;	/* Vnode of executable. */
	int	p_holdcnt;		/* If non-zero, don't swap. */
	sigset_t p_sigmask;	/* DEPRECATED. */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */
	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];
	struct 	pgrp *p_pgrp;	/* Pointer to process group. */
	struct	user *p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	struct	rusage *p_ru;	/* Exit information. XXX */
};


// bsd/sys/sysctl.h
struct kinfo_proc {
	struct  extern_proc kp_proc;                    /* proc structure */
	struct  eproc {
		struct  proc *e_paddr;          /* address of proc */
		struct  session *e_sess;        /* session pointer */
		struct  _pcred e_pcred;         /* process credentials */
		struct  _ucred e_ucred;         /* current credentials */
		struct   vmspace e_vm;          /* address space */
		pid_t   e_ppid;                 /* parent process id */
		pid_t   e_pgid;                 /* process group id */
		short   e_jobc;                 /* job control counter */
		dev_t   e_tdev;                 /* controlling tty dev */
		pid_t   e_tpgid;                /* tty process group id */
		struct  session *e_tsess;       /* tty session pointer */
#define WMESGLEN        7
		char    e_wmesg[WMESGLEN+1];    /* wchan message */
		segsz_t e_xsize;                /* text size */
		short   e_xrssize;              /* text rss */
		short   e_xccount;              /* text references */
		short   e_xswrss;
		int32_t e_flag;
#define EPROC_CTTY      0x01    /* controlling tty vnode active */
#define EPROC_SLEADER   0x02    /* session leader */
#define COMAPT_MAXLOGNAME       12
		char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
#if CONFIG_LCTX
		pid_t   e_lcid;
		int32_t e_spare[3];
#else
		int32_t e_spare[4];
#endif
	} kp_eproc;
};


// 64 bits stuff

struct user_vmspace {
	int             vm_refcnt;      /* number of references */
	user_addr_t     vm_shm __attribute((aligned(8)));                       /* SYS5 shared memory private data XXX */
	segsz_t         vm_rssize;              /* current resident set size in pages */
	segsz_t         vm_swrss;               /* resident set size before last swap */
	segsz_t         vm_tsize;               /* text size (pages) XXX */
	segsz_t         vm_dsize;               /* data size (pages) XXX */
	segsz_t         vm_ssize;               /* stack size (pages) */
	user_addr_t     vm_taddr __attribute((aligned(8)));       /* user virtual address of text XXX */
	user_addr_t     vm_daddr;       /* user virtual address of data XXX */
	user_addr_t vm_maxsaddr;        /* user VA at max stack growth */
};


struct user64_pcred {
	char    pc_lock[72];            /* opaque content */
	user64_addr_t   pc_ucred;       /* Current credentials. */
	uid_t   p_ruid;                 /* Real user id. */
	uid_t   p_svuid;                /* Saved effective user id. */
	gid_t   p_rgid;                 /* Real group id. */
	gid_t   p_svgid;                /* Saved effective group id. */
	int     p_refcnt;               /* Number of references. */
};


struct user64_extern_proc {
	union {
		struct {
			user_addr_t __p_forw;   /* Doubly-linked run/sleep queue. */
			user_addr_t __p_back;
		} p_st1;
		struct user64_timeval __p_starttime;    /* process start time */
	} p_un;
	user_addr_t     p_vmspace;      /* Address space. */
	user_addr_t             p_sigacts;      /* Signal actions, state (PROC ONLY). */
	int             p_flag;                 /* P_* flags. */
	char    p_stat;                 /* S* process status. */
	pid_t   p_pid;                  /* Process identifier. */
	pid_t   p_oppid;                /* Save parent pid during ptrace. XXX */
	int             p_dupfd;                /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	user_addr_t user_stack __attribute((aligned(8)));       /* where user stack was allocated */
	user_addr_t exit_thread;  /* XXX Which thread is exiting? */
	int             p_debugger;             /* allow to debug */
	boolean_t       sigwait;        /* indication to suspend */
	/* scheduling */
	u_int   p_estcpu;        /* Time averaged value of p_cpticks. */
	int             p_cpticks;       /* Ticks of cpu time. */
	fixpt_t p_pctcpu;        /* %cpu for this process during p_swtime */
	user_addr_t     p_wchan __attribute((aligned(8)));       /* Sleep address. */
	user_addr_t     p_wmesg;         /* Reason for sleep. */
	u_int   p_swtime;        /* Time swapped in or out. */
	u_int   p_slptime;       /* Time since last blocked. */
	struct  user64_itimerval p_realtimer;   /* Alarm timer. */
	struct  user64_timeval p_rtime; /* Real time. */
	u_quad_t p_uticks;              /* Statclock hits in user mode. */
	u_quad_t p_sticks;              /* Statclock hits in system mode. */
	u_quad_t p_iticks;              /* Statclock hits processing intr. */
	int             p_traceflag;            /* Kernel trace points. */
	user_addr_t     p_tracep __attribute((aligned(8)));     /* Trace to vnode. */
	int             p_siglist;              /* DEPRECATED */
	user_addr_t     p_textvp __attribute((aligned(8)));     /* Vnode of executable. */
	int             p_holdcnt;              /* If non-zero, don't swap. */
	sigset_t p_sigmask;     /* DEPRECATED. */
	sigset_t p_sigignore;   /* Signals being ignored. */
	sigset_t p_sigcatch;    /* Signals being caught by user. */
	u_char  p_priority;     /* Process priority. */
	u_char  p_usrpri;       /* User-priority based on p_cpu and p_nice. */
	char    p_nice;         /* Process "nice" value. */
	char    p_comm[MAXCOMLEN+1];
	user_addr_t     p_pgrp __attribute((aligned(8)));       /* Pointer to process group. */
	user_addr_t     p_addr; /* Kernel virtual addr of u-area (PROC ONLY). */
	u_short p_xstat;        /* Exit status for wait; also stop signal. */
	u_short p_acflag;       /* Accounting flags. */
	user_addr_t     p_ru __attribute((aligned(8))); /* Exit information. XXX */
};


struct user64_kinfo_proc {
	struct  user64_extern_proc kp_proc;     /* proc structure */
	struct  user64_eproc {
		user_addr_t e_paddr;            /* address of proc */
		user_addr_t e_sess;                     /* session pointer */
		struct  user64_pcred e_pcred;           /* process credentials */
		struct  _ucred e_ucred;         /* current credentials */
		struct   user_vmspace e_vm; /* address space */
		pid_t   e_ppid;                 /* parent process id */
		pid_t   e_pgid;                 /* process group id */
		short   e_jobc;                 /* job control counter */
		dev_t   e_tdev;                 /* controlling tty dev */
		pid_t   e_tpgid;                /* tty process group id */
		user64_addr_t   e_tsess __attribute((aligned(8)));      /* tty session pointer */
		char    e_wmesg[WMESGLEN+1];    /* wchan message */
		segsz_t e_xsize;                /* text size */
		short   e_xrssize;              /* text rss */
		short   e_xccount;              /* text references */
		short   e_xswrss;
		int32_t e_flag;
		char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
#if CONFIG_LCTX
		pid_t   e_lcid;
		int32_t e_spare[3];
#else
		int32_t e_spare[4];
#endif
	} kp_eproc;
};

#endif
