/*
 * ________                        
 * \_____  \   ____ ___.__.___  ___
 *  /   |   \ /    <   |  |\  \/  /
 * /    |    \   |  \___  | >    < 
 * \_______  /___|  / ____|/__/\_ \
 *         \/     \/\/           \/ 
 *                    The Black Cat
 *
 * Copyright (c) fG!, 2011, 2012, 2013, 2014, 2015, 2016 - reverser@put.as - https://reverse.put.as
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
#include <sys/malloc.h>

#include "my_data_definitions.h"
#include "disasm_utils.h"
#include "kernel_info.h"
#include "cpu_protections.h"

extern struct kernel_info g_kernel_info;

struct patches patches_head = SLIST_HEAD_INITIALIZER(patches_head);

/* find all locations we might want to patch */
kern_return_t
find_patch_locations(void)
{
    /* find resume flag */
    mach_vm_address_t machine_thread_set_state_addr = solve_kernel_symbol(&g_kernel_info, "_machine_thread_set_state");
    if (machine_thread_set_state_addr)
    {
        if (find_resume_flag(machine_thread_set_state_addr, &patches_head) != KERN_SUCCESS)
        {
            LOG_ERROR("Can't find locations to patch resume flag!");
            return KERN_FAILURE;
        }
    }
    else
    {
        LOG_ERROR("Failed to find machine_thread_set_state symbol address.");
        return KERN_FAILURE;
    }

    /* find task_for_pid */
    mach_vm_address_t task_for_pid_addr = solve_kernel_symbol(&g_kernel_info, "_task_for_pid");
    if (task_for_pid_addr)
    {
        if (find_task_for_pid(task_for_pid_addr, &patches_head))
        {
            LOG_ERROR("Can't find location to patch task_for_pid()!");
            return KERN_FAILURE;
        }
    }
    else
    {
        LOG_ERROR("Failed to find task_for_pid symbol address.");
        return KERN_FAILURE;
    }

    /* find kauth */
    mach_vm_address_t ptrace_addr = solve_kernel_symbol(&g_kernel_info, "_ptrace");
    mach_vm_address_t kauth_authorize_process_addr = solve_kernel_symbol(&g_kernel_info, "_kauth_authorize_process");
    if (ptrace_addr && kauth_authorize_process_addr)
    {
        if (find_kauth(ptrace_addr, kauth_authorize_process_addr, &patches_head))
        {
            LOG_ERROR("Can't find location to patch kauth!");
            return KERN_FAILURE;
        }
    }
    else
    {
        LOG_ERROR("Failed to find ptrace or kauth_authorize_process symbol address.");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

kern_return_t
cleanup_patch_locations(void)
{
    struct patch_location *el = NULL;
    struct patch_location *tmp = NULL;
    SLIST_FOREACH_SAFE(el, &patches_head, next, tmp)
    {
        SLIST_REMOVE(&patches_head, el, patch_location, next);
        _FREE(el, M_TEMP);
    }
    return KERN_SUCCESS;
}

/*
 * function to enable/disable the x86 resume flag bit that is cleared by XNU kernel
 */
kern_return_t
patch_resume_flag(int cmd)
{
    // patch bytes
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            if (el->type == kPatch_resume)
            {
                int offset = el->size - 4;
                *(uint32_t*)(el->address + offset) = 0xFFFF8DFF;
            }
        }
        disable_kernel_write();
    }
    // restore original bytes
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            if (el->type == kPatch_resume)
            {
                memcpy(el->address, el->orig_bytes, el->size);
            }
        }
        disable_kernel_write();
    }
    return KERN_SUCCESS;
}

/*
 * patch the task_for_pid() so we can do it for kernel pid
 *
 * this is the structure used in the mach call:
 struct task_for_pid_args {
 PAD_ARG_(mach_port_name_t, target_tport);
 PAD_ARG_(int, pid);
 PAD_ARG_(user_addr_t, t);
 };

 * The disassembly changed in Mavericks so the old method fails with it.
 * Best method is to find out where pid member is stored and then locate where it is tested.
 * Mountain Lion:
 __text:FFFFFF80005C8650 55                                      push    rbp
 __text:FFFFFF80005C8651 48 89 E5                                mov     rbp, rsp
 __text:FFFFFF80005C8654 41 57                                   push    r15
 __text:FFFFFF80005C8656 41 56                                   push    r14
 __text:FFFFFF80005C8658 41 55                                   push    r13
 __text:FFFFFF80005C865A 41 54                                   push    r12
 __text:FFFFFF80005C865C 53                                      push    rbx
 __text:FFFFFF80005C865D 48 83 EC 18                             sub     rsp, 18h
 __text:FFFFFF80005C8661 4C 8B 77 10                             mov     r14, [rdi+10h]
 __text:FFFFFF80005C8665 8B 1F                                   mov     ebx, [rdi]
 __text:FFFFFF80005C8667 44 8B 7F 08                             mov     r15d, [rdi+8]
 (...)
 __text:FFFFFF80005C86F8 45 85 FF                                test    r15d, r15d ; if (pid == 0) {
 __text:FFFFFF80005C86FB 75 55                                   jnz     short loc_FFFFFF80005C8752
 
 * Mavericks:
 __text:FFFFFF80006385A0                 push    rbp
 __text:FFFFFF80006385A1                 mov     rbp, rsp
 __text:FFFFFF80006385A4                 push    r15
 __text:FFFFFF80006385A6                 push    r14
 __text:FFFFFF80006385A8                 push    r13
 __text:FFFFFF80006385AA                 push    r12
 __text:FFFFFF80006385AC                 push    rbx
 __text:FFFFFF80006385AD                 sub     rsp, 28h
 __text:FFFFFF80006385B1                 mov     rax, [rdi+10h]
 __text:FFFFFF80006385B5                 mov     [rbp+var_48], rax
 __text:FFFFFF80006385B9                 mov     ebx, [rdi]
 __text:FFFFFF80006385BB                 mov     r12d, [rdi+8]
 (...)
 __text:FFFFFF8000638608                 test    r12d, r12d ; if (pid == 0) {
 __text:FFFFFF800063860B                 jz      loc_FFFFFF800063877F
 
 */
kern_return_t
patch_task_for_pid(int cmd)
{
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        // XXX: somewhat fragile assumptions going on here ;-) Beware!
        // if it's a JZ we NOP everything
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            if (el->type == kPatch_taskforpid)
            {
                if (el->jmp == 0)
                {
                    memset(el->address, 0x90, el->size);
                }
                // if it's a JNZ we convert into a JMP
                else if (el->jmp == 1)
                {
                    // XXX: let's trust our luck and assume it's a short jump
                    if (el->size == 2)
                    {
                        memset(el->address, 0xEB, 1);
                    }
                    else if (el->size == 6)
                    {
                        memset(el->address, 0x90, 1);
                        memset(el->address+1, 0xE9, 1);
                    }
                }
                
            }
        }
        disable_kernel_write();
    }
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            memcpy(el->address, el->orig_bytes, el->size);
        }
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
    if (cmd == ENABLE)
    {
        enable_kernel_write();
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            if (el->type == kPatch_kauth)
            {
                /* JNZ is modified to NOP */
                if (el->jmp == 1)
                {
                    memset(el->address, 0x90, el->size);
                }
                /* JZ modified to JMP */
                else if (el->jmp == 0)
                {
                    /* expected near jump */
                    if (el->size == 6)
                    {
                        /* near jump is 5 bytes, conditional six so patch first and change next to E9 */
                        memset(el->address, 0x90, 1);
                        memset(el->address+1, 0xE9, 1);
                    }
                    else if (el->size == 2)
                    {
                        memset(el->address, 0xEB, 1);
                    }
                }
            }
        }
        disable_kernel_write();
    }
    else if (cmd == DISABLE)
    {
        enable_kernel_write();
        struct patch_location *el = NULL;
        SLIST_FOREACH(el, &patches_head, next)
        {
            if (el->type == kPatch_kauth)
            {
                memcpy(el->address, el->orig_bytes, el->size);
            }
        }
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
    LOG_DEBUG("Old MSR bits: ");
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
    LOG_DEBUG("New MSR bits: ");
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
