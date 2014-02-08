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
 * antidebug.c
 *
 * Implements anti-anti-debugging features
 *
 */

#include "antidebug.h"
#include <sys/kernel_types.h>
#include <sys/proc.h>

#include "sysent.h"
#include "proc.h"
#include "my_data_definitions.h"
#include "cpu_protections.h"

/* ptrace request */
#define PT_DENY_ATTACH          31
#define P_LNOATTACH     0x00001000
#define P_LTRACED       0x00000400

/* Macros to clear/set/test flags. */
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

// external variables
extern void *g_sysent_addr;
extern struct sysent *g_sysent;
extern struct sysent_mavericks *g_sysent_mav;
extern const int  version_major;

// prototypes
int (*real_ptrace)(struct proc *, struct ptrace_args *, int *);
int (*real_sysctl)(struct proc *, struct __sysctl_args *, int *);
int onyx_ptrace(struct proc *, struct ptrace_args *, int *);
int onyx_sysctl(struct proc *, struct __sysctl_args *, int *);

#pragma mark Functions that install and remove sysent hooks

kern_return_t
anti_ptrace(int cmd)
{
    LOG_DEBUG("Executing anti_ptrace!");
    // Mountain Lion moved sysent[] to read-only section :-)
    enable_kernel_write();
    if (cmd == DISABLE)
    {
        // restore the pointer to the original function
        if (version_major >= MAVERICKS)
        {
            if (real_ptrace != NULL)
            {
                g_sysent_mav[SYS_ptrace].sy_call = (sy_call_t *)real_ptrace;
            }
            else
            {
                LOG_ERROR("No pointer available for original ptrace() function!");
                return KERN_FAILURE;
            }
        }
        else
        {
            if (real_ptrace != NULL)
            {
                g_sysent[SYS_ptrace].sy_call = (sy_call_t *)real_ptrace;
            }
            else
            {
                LOG_ERROR("No pointer available for original ptrace() function!");
                return KERN_FAILURE;
            }
        }
    }
    else if (cmd == ENABLE)
    {
        if (version_major >= MAVERICKS)
        {
            // save address of the real function
            real_ptrace = (void*)g_sysent_mav[SYS_ptrace].sy_call;
            // hook the syscall by replacing the pointer in sysent
            g_sysent_mav[SYS_ptrace].sy_call = (sy_call_t *)onyx_ptrace;
        }
        else
        {
            real_ptrace = (void*)g_sysent[SYS_ptrace].sy_call;
            g_sysent[SYS_ptrace].sy_call = (sy_call_t *)onyx_ptrace;
        }
    }
    disable_kernel_write();
    return KERN_SUCCESS;
}

kern_return_t
anti_sysctl(int cmd)
{
    enable_kernel_write();
    if (cmd == DISABLE)
    {
        if (version_major >= MAVERICKS)
        {
            if (real_sysctl != NULL)
            {
                g_sysent_mav[SYS___sysctl].sy_call = (sy_call_t *)real_sysctl;
            }
            else
            {
                LOG_ERROR("No pointer available for original sysctl() function!");
                return KERN_FAILURE;
            }
        }
        else
        {
            if (real_sysctl != NULL)
            {
                g_sysent[SYS___sysctl].sy_call = (sy_call_t *)real_sysctl;
            }
            else
            {
                LOG_ERROR("No pointer available for original sysctl() function!");
                return KERN_FAILURE;
            }
        }
    }
    else if (cmd == ENABLE)
    {
        if (version_major >= MAVERICKS)
        {
            real_sysctl = (void*)g_sysent_mav[SYS___sysctl].sy_call;
            g_sysent_mav[SYS___sysctl].sy_call = (sy_call_t *)onyx_sysctl;
        }
        else
        {
            real_sysctl = (void*)g_sysent[SYS___sysctl].sy_call;
            g_sysent[SYS___sysctl].sy_call = (sy_call_t *)onyx_sysctl;
        }
    }
    disable_kernel_write();
    return KERN_SUCCESS;
}

#pragma mark The hook replacement functions

/*
 * Hijack ptrace syscall
 * This will allow to bypass the PT_DENY_ATTACH and P_LNOATTACH (flag that denies dtrace tracing)
 * Piece of code from ptrace @ xnu/bsd/kern/mach_process.c:

 if (uap->req == PT_DENY_ATTACH) {
    proc_lock(p);
    if (ISSET(p->p_lflag, P_LTRACED)) {
        proc_unlock(p);
        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_FRCEXIT) | DBG_FUNC_NONE,
                              p->p_pid, W_EXITCODE(ENOTSUP, 0), 4, 0, 0);
        exit1(p, W_EXITCODE(ENOTSUP, 0), retval);
        // drop funnel before we return
        thread_exception_return();
        // NOTREACHED
    }
    SET(p->p_lflag, P_LNOATTACH);
    proc_unlock(p);
    
    return(0);
}

 * If target process is being traced (P_LTRACED) when the PT_DENY_ATTACH request is issued then
 * it will exit.
 * If it's not being traced, the flag P_LNOATTACH will be activated.
 * This flag will be verified later when PT_ATTACH request is issued. There is a default kauth which
 * will be responsible for this check (kauth_authorize_process). It calls cantrace().
 
if (ISSET(traced_procp->p_lflag, P_LNOATTACH)) {
    *errp = EBUSY;
    return (0);
}

 * So if PT_DENY_ATTACH is activated then P_LNOATTACH is activated too (a local flag (p_lflag) is set)
 * Since we have hijacked that request, P_LNOATTACH will never be set so DTrace can work normally :).
 *
 * The following simple dtrace script can be used to test this:
 
syscall::open*:entry
/execname == "iTunes"/
{
ustack();
}

 * Try to use this script with ptrace anti-anti-debug active and then disable it and try again
 * (don't forget you need to quit iTunes before trying again).
 * Without anti-anti-debug you will get lots of errors.
 */
int 
onyx_ptrace(struct proc *p, struct ptrace_args *uap, int *retval)
{
	char processname[MAXCOMLEN+1];
    // verify if it's a PT_DENY_ATTACH request and fix for all processes that call it
    if (uap->req == PT_DENY_ATTACH)
    {
        /* retrieve pid using exported functions so we don't need definition of struct proc */
        pid_t pid = proc_pid(p);
        proc_name(pid, processname, sizeof(processname));
        LOG_INFO("Blocked PT_DENY_ATTACH/P_LNOATTACH in PID %d (%s)", pid, processname);
        return 0;
    }
    // else it's business as usual, we are not interested in messing with other requests
    else
    {
        return real_ptrace(p, uap, retval);
    }
}


/*
 * our sysctl so we can intercept the anti-debug call
 * the anti-debug trick is described here:
 * http://developer.apple.com/library/mac/qa/qa1361/_index.html
 */
int 
onyx_sysctl(struct proc *p, struct __sysctl_args *uap, int *retval)
{
	int mib[4];
	int result;
	char processname[MAXCOMLEN+1];
	// call the real_sysctl function and hold the result so we can use it to return from our hijacked sysctl
	result = real_sysctl(p,uap,retval);
	/*
	 **************************************************
	 How to bypass the anti-debug protection:
	 If we copy the kinfo_proc structure to kernel space and edit the p_flag and copy back to userspace,
	 then we can bypass the anti-debug protection
	 ***************************************************
	 */
    // int copyin(const void *uaddr, void *kaddr, size_t len);
    // copyin() Copies len bytes of data from the user-space address uaddr to the kernel-space address kaddr.
    // copy structure from userspace to kernel space so we can verify if it's what we are looking for
    copyin(uap->name, &mib, sizeof(mib));
    // if it's a anti-debug call
    //printf("[onyx-the-black-cat] DEBUG: sysctl parameters mib[0]: %x mib[1]: %x mib[2]: %x\n", mib[0], mib[1], mib[2]);
    if (mib[0]==CTL_KERN && mib[1]==KERN_PROC && mib[2]==KERN_PROC_PID)
    {
        // copy process name
        pid_t pid = proc_pid(p);
        proc_name(pid, processname, sizeof(processname));
        // is it a 64bits process?
        if (proc_is64bit(p) == 1)
        {
            struct user64_kinfo_proc kpr;
            // then copy the result from the destination buffer ( *oldp from sysctl call) to kernel space so we can edit
            copyin(uap->old, &kpr, sizeof(kpr));
            if ( (kpr.kp_proc.p_flag & P_TRACED) != 0 )
            {
                // we can display the PID of the calling program, which can be useful
                LOG_INFO("Detected sysctl anti-debug trick requested by 64 bits process with PID %d (%s)! Patching...", pid, processname);
                // modify the p_flag because:
                // We're being debugged if the P_TRACED flag is set.
                // return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
                kpr.kp_proc.p_flag = kpr.kp_proc.p_flag & ~P_TRACED;
                // copy back to user space the modified structure
                // int copyout(const void *kaddr, void *uaddr, size_t len);
                // copyout() Copies len bytes of data from the kernel-space address kaddr to the user-space address uaddr.
                copyout(&kpr, uap->old,sizeof(kpr));
                /* sysctl()
                 If the old value is not desired, oldp and
                 oldlenp should be set to NULL.
                 */
            }
        }
        // 32 bits processes
        else
        {
            struct kinfo_proc kpr;
            copyin(uap->old, &kpr, sizeof(kpr));
            if ( (kpr.kp_proc.p_flag & P_TRACED) != 0 )
            {
                LOG_INFO("Detected sysctl anti-debug trick requested by 32 bits process with PID %d (%s)! Patching...", pid, processname);
                kpr.kp_proc.p_flag = kpr.kp_proc.p_flag & ~P_TRACED;
                copyout(&kpr, uap->old,sizeof(kpr));
            }
            
        }
    }
	// and return from our hijacked function
	return result;
}
