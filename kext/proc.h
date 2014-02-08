/*
 * ________                        
 * \_____  \   ____ ___.__.___  ___
 *  /   |   \ /    <   |  |\  \/  /
 * /    |    \   |  \___  | >    < 
 * \_______  /___|  / ____|/__/\_ \
 *         \/     \/\/           \/ 
 *                    The Black Cat
 *
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
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

/* NOTE: all these structures are unmodified since Snow Leopard up to Mavericks */

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
// @ bsd/sys/vm.h
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

// @ bsd/sys/sysctl.h
struct user64_pcred {
	char    pc_lock[72];            /* opaque content */
	user64_addr_t   pc_ucred;       /* Current credentials. */
	uid_t   p_ruid;                 /* Real user id. */
	uid_t   p_svuid;                /* Saved effective user id. */
	gid_t   p_rgid;                 /* Real group id. */
	gid_t   p_svgid;                /* Saved effective group id. */
	int     p_refcnt;               /* Number of references. */
};

// @ bsd/sys/proc_internal.h
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

#define CONFIG_LCTX 1
// @ bsd/sys/sysctl.h
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
