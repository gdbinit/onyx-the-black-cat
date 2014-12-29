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
 * Based on original code by Landon J. Fuller <landonf@opendarwin.org>
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
 * onyx_the_black_cat.c
 *
 */

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <i386/proc_reg.h>
#include <mach/kmod.h>

#include "my_data_definitions.h"
#include "kernel_control.h"
#include "sysent.h"
#include "syscall.h"
#include "kernel_info.h"
#include "disasm_utils.h"
#include "patchkernel.h"

#define VERSION "3.0"

/* globals */
struct kernel_info g_kernel_info;
extern const int version_major;

/*
 * THE FUN STARTS HERE
 */
kern_return_t 
onyx_the_black_cat_start (kmod_info_t * ki, void * d) 
{
    printf(
           " _____                 \n"
           "|     |___ _ _ _ _     \n"
           "|  |  |   | | |_'_|    \n"
           "|_____|_|_|_  |_,_|    \n"
           "          |___|        \n"
           "      The Black Cat v%s\n", VERSION);
    
    /* needs to be updated for every new major version supported */
    if (version_major > YOSEMITE)
    {
        LOG_ERROR("Only Yosemite or lower supported!");
        return KERN_FAILURE;
    }
    
    /* install the kernel control so we can enable/disable features */
    install_kern_control();
    /* locate sysent table */
    mach_vm_address_t kernel_base = 0;
    if (find_sysent(&kernel_base) != KERN_SUCCESS)
    {
        return KERN_FAILURE;
    }
    /* read kernel info from the disk image */
    if (init_kernel_info(&g_kernel_info, kernel_base) != KERN_SUCCESS)
    {
        return KERN_FAILURE;
    }

	return KERN_SUCCESS;
}

/*
 * THE FUN ENDS HERE :-(
 */
kern_return_t 
onyx_the_black_cat_stop (kmod_info_t * ki, void * d) 
{
	// remove the kernel control socket
    if (remove_kern_control() != KERN_SUCCESS)
    {
        return KERN_FAILURE;
    }

    // remove all sysent hijacks
	cleanup_sysent();
    // remove any patches
    patch_resume_flag(DISABLE);
    patch_task_for_pid(DISABLE);
    patch_kauth(DISABLE);
    // ALL DONE
	return KERN_SUCCESS;
}

