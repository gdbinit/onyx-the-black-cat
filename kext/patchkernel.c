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
 * patchkernel.c
 *
 * Functions to patch kernel features
 *
 */

#include "patchkernel.h"
#include <sys/types.h>
#include <string.h>
#include <libkern/libkern.h>
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
    static struct rf_location *patch_locations = NULL;
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
        disable_wp();
        disable_interrupts();
        struct rf_location *tmp = NULL;
        LL_FOREACH(patch_locations, tmp)
        {
            int offset = tmp->size - 4;
            *(uint32_t*)(tmp->address + offset) = 0xFFFF8DFF;
        }
        enable_wp();
        enable_interrupts();
    }
    // restore original bytes
    else if (cmd == DISABLE)
    {
        disable_wp();
        disable_interrupts();
        struct rf_location *tmp = NULL;
        LL_FOREACH(patch_locations, tmp)
        {
            memcpy(tmp->address, tmp->orig_bytes, tmp->size);
        }
        enable_wp();
        enable_interrupts();
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
    return KERN_SUCCESS;
}

/*
 * patch the kauth process so it will never deny the requests
 *
 */
kern_return_t
patch_kauth(int cmd)
{
    return KERN_SUCCESS;
}
