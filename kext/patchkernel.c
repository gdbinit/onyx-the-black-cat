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
 * patchkernel.c
 *
 * Functions to patch kernel features
 *
 */

#include "patchkernel.h"
#include <sys/types.h>
#include <string.h>
#include <libkern/libkern.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/locks.h>

#include "my_data_definitions.h"
#include "disasm_utils.h"
#include "kernel_info.h"
#include "cpu_protections.h"
#include "utlist.h"

extern struct kernel_info g_kernel_info;

/*
 * function to enable/disable the x86 resume flag bit that is cleared by XNU kernel
 */
kern_return_t
patch_resume_flag(int cmd)
{
    static struct patch_location *patch_locations = NULL;
    // get the locations we need to patch
    if (patch_locations == NULL)
    {
        mach_vm_address_t symbol_addr = solve_kernel_symbol(&g_kernel_info, "_machine_thread_set_state");
        if (symbol_addr)
        {
            find_resume_flag(symbol_addr, &patch_locations);
        }
    }
    // patch bytes
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        struct patch_location *tmp = NULL;
        LL_FOREACH(patch_locations, tmp)
        {
            int offset = tmp->size - 4;
            *(uint32_t*)(tmp->address + offset) = 0xFFFF8DFF;
        }
        disable_kernel_write();
    }
    // restore original bytes
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        struct patch_location *tmp = NULL;
        LL_FOREACH(patch_locations, tmp)
        {
            memcpy(tmp->address, tmp->orig_bytes, tmp->size);
        }
        disable_kernel_write();
    }
    return KERN_SUCCESS;
}

/*
 * patch the task_for_pid() so we can do it for kernel pid
 *
 */
kern_return_t
patch_task_for_pid(int cmd)
{
    static struct patch_location patch = {0};
    
    if (patch.address == 0)
    {
        mach_vm_address_t task_for_pid_sym = solve_kernel_symbol(&g_kernel_info, "_task_for_pid");
        mach_vm_address_t audit_arg_mach_port1_sym = solve_kernel_symbol(&g_kernel_info, "_audit_arg_mach_port1");
        if (task_for_pid_sym && audit_arg_mach_port1_sym)
        {
            if  (find_task_for_pid(task_for_pid_sym, audit_arg_mach_port1_sym, &patch))
            {
                LOG_MSG("[ERROR] Can't find location to patch task_for_pid()!\n");
                return KERN_FAILURE;
            }
        }
        else
        {
            LOG_MSG("[ERROR] Can't solve required symbols to patch task_for_pid()\n");
            return KERN_FAILURE;
        }
    }
    
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        // XXX: somewhat fragile assumptions going on here ;-) Beware!
        // if it's a JZ we NOP everything
        if (patch.jmp == 0)
        {
            memset(patch.address, 0x90, patch.size);
        }
        // if it's a JNZ we convert into a JMP
        else if (patch.jmp == 1)
        {
            // XXX: let's trust our luck and assume it's a short jump
            memset(patch.address, 0xEB, 1);
        }
        disable_kernel_write();
    }
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        memcpy(patch.address, patch.orig_bytes, patch.size);
        disable_kernel_write();
    }
    return KERN_SUCCESS;
}

/*
 * patch the kauth process so it will never deny the requests
 *
 */
kern_return_t
patch_kauth(int cmd)
{
    static struct patch_location patch = {0};
    if (patch.address == 0)
    {
        mach_vm_address_t ptrace_sym = solve_kernel_symbol(&g_kernel_info, "_ptrace");
        mach_vm_address_t kauth_authorize_process_sym = solve_kernel_symbol(&g_kernel_info, "_kauth_authorize_process");
        if (ptrace_sym && kauth_authorize_process_sym)
        {
            if (find_kauth(ptrace_sym, kauth_authorize_process_sym, &patch))
            {
                LOG_MSG("[ERROR] Can't find location to patch kauth!\n");
                return KERN_FAILURE;
            }
        }
        else
        {
            LOG_MSG("[ERROR] Can't solve required symbols to patch kauth()\n");
            return KERN_FAILURE;
        }
    }
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        memset(patch.address, 0x90, patch.size);
        disable_kernel_write();
    }
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        memcpy(patch.address, patch.orig_bytes, patch.size);
        disable_kernel_write();
    }
    return KERN_SUCCESS;
}

/*
 * Modify MSR value
 * We modify MSR to activate single-step-on-branches.
 * This requires ring 0 privileges.
 */
kern_return_t
patch_singlestep(int cmd)
{
    u_int64_t msr;
    int i, k, mask;
    // read current debug MSR
    msr = rdmsr64(MSR_IA32_DEBUGCTLMSR);
    LOG_DEBUG("[DEBUG] Old MSR bits: ");
    for (i = 7; i>=0; i--)
    {
        mask = 1 << i;
        k = msr & mask;
        if (k == 0)
        {
            printf("%d:0 ",i);
        }
        else
        {
            printf("%d:1 ",i);
        }
    }
    printf("\n");
    // enable only that bit 1
    wrmsr64(MSR_IA32_DEBUGCTLMSR,0x2);
    // verify our operation
    msr = rdmsr64(MSR_IA32_DEBUGCTLMSR);
    LOG_DEBUG("[DEBUG] New MSR bits: ");
    for (i = 7; i>=0; i--)
    {
        mask = 1 << i;
        k = msr & mask;
        if (k == 0)
        {
            printf("%d:0 ",i);
        }
        else
        {
            printf("%d:1 ",i);
        }
    }
    printf("\n");
    return KERN_SUCCESS;
}
