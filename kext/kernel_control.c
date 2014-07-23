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
 * kernel_control.c
 *
 * Implements kernel control socket
 *
 */

#include "kernel_control.h"

#include <sys/conf.h>
#include <sys/kernel.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h>
#include <sys/param.h>
#include <stdint.h>
#include <sys/kern_control.h>

#include "shared_data.h"
#include "my_data_definitions.h"
#include "sysent.h"
#include "patchkernel.h"
#include "antidebug.h"

// local prototypes
static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

// local globals
static int g_max_clients;
static kern_ctl_ref g_ctl_ref;
static u_int32_t g_client_unit = 0;
static kern_ctl_ref g_client_ctl_ref = NULL;
static boolean_t g_kern_ctl_registered = FALSE;

#pragma mark Kernel Control struct and handler functions

// described at Network Kernel Extensions Programming Guide
static struct kern_ctl_reg g_ctl_reg = {
	BUNDLE_ID,            /* use a reverse dns name which includes a name unique to your comany */
	0,				   	  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
	0,					  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
	0,                    /* no privileged access required to access this filter */
	0,					  /* use default send size buffer */
	0,                    /* Override receive buffer size */
	ctl_connect,		  /* Called when a connection request is accepted */
	ctl_disconnect,		  /* called when a connection becomes disconnected */
	NULL,				  /* ctl_send_func - handles data sent from the client to kernel control - not implemented */
	ctl_set,			  /* called when the user process makes the setsockopt call */
	NULL			 	  /* called when the user process makes the getsockopt call */
};

#pragma mark The start and stop functions

kern_return_t
install_kern_control(void)
{
    errno_t error = 0;
    // register the kernel control
    error = ctl_register(&g_ctl_reg, &g_ctl_ref);
    if (error == 0)
    {
        g_kern_ctl_registered = TRUE;
        LOG_DEBUG("Onyx kernel control installed successfully!");
        return KERN_SUCCESS;
    }
    else
    {
        LOG_ERROR("Failed to install Onyx kernel control!");
        return KERN_FAILURE;
    }
}

kern_return_t
remove_kern_control(void)
{
    errno_t error = 0;
    // remove kernel control
    error = ctl_deregister(g_ctl_ref);
    switch (error)
    {
        case 0:
        {
            return KERN_SUCCESS;
        }
        case EINVAL:
        {
            LOG_ERROR("The kernel control reference is invalid.");
            return KERN_FAILURE;
        }
        case EBUSY:
        {
            LOG_ERROR("The kernel control still has clients attached. Please disconnect them first!");
            return KERN_FAILURE;
        }
        default:
            return KERN_FAILURE;
    }
}

#pragma mark Kernel Control handler functions

/*
 * called when a client connects to the socket
 * we need to store some info to use later
 */
static int
ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    // we only accept a single client
    if (g_max_clients > 0)
    {
        return EBUSY;
    }
    g_max_clients++;
    // store the unit id and ctl_ref of the client that connected
    // we will need these to queue data to userland
    g_client_unit = sac->sc_unit;
    g_client_ctl_ref = ctl_ref;
    LOG_DEBUG("Client connected!");
    return 0;
}

/*
 * and when client disconnects
 */
static errno_t
ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    // reset some vars
    g_max_clients = 0;
    g_client_unit = 0;
    g_client_ctl_ref = NULL;
    return 0;
}

/*
 * send data from userland to kernel
 * this is how userland apps adds and removes apps to be suspended
 */
static int
ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int error = 0;
    if (len == 0 || data == NULL)
    {
        LOG_ERROR("Invalid data to command.");
        return EINVAL;
    }
    // XXX: lame authentication :-]
    if (strcmp((char*)data, MAGIC) != 0)
    {
        LOG_ERROR("Invalid spell!");
        return EINVAL;
    }
        
	switch (opt)
	{
        case PATCH_TASK_FOR_PID:
        {
            LOG_DEBUG("Received request to patch task_for_pid.");
            patch_task_for_pid(ENABLE);
            break;
        }
        case UNPATCH_TASK_FOR_PID:
        {
            LOG_DEBUG("Received request to restore task_for_pid.");
            patch_task_for_pid(DISABLE);
            break;
        }
        case ANTI_PTRACE_ON:
        {
            LOG_DEBUG("Received request to patch ptrace.");
            anti_ptrace(ENABLE);
            break;
        }
        case ANTI_PTRACE_OFF:
        {
            LOG_DEBUG("Received request to restore ptrace.");
            anti_ptrace(DISABLE);
            break;
        }
        case ANTI_SYSCTL_ON:
        {
            LOG_DEBUG("Received request to patch sysctl.");
            anti_sysctl(ENABLE);
            break;
        }
        case ANTI_SYSCTL_OFF:
        {
            LOG_DEBUG("Received request to restore sysctl.");
            anti_sysctl(DISABLE);
            break;
        }
        case ANTI_KAUTH_ON:
        {
            LOG_DEBUG("Received request to patch kauth.");
            patch_kauth(ENABLE);
            break;
        }
        case ANTI_KAUTH_OFF:
        {
            LOG_DEBUG("Received request to restore kauth.");
            patch_kauth(DISABLE);
            break;
        }
        case PATCH_RESUME_FLAG:
        {
            LOG_DEBUG("Received request to patch resume flag.");
            patch_resume_flag(ENABLE);
            break;
        }
        case UNPATCH_RESUME_FLAG:
        {
            LOG_DEBUG("Received request to restore resume flag.");
            patch_resume_flag(DISABLE);
            break;
        }
        case PATCH_SINGLESTEP:
        {
            LOG_DEBUG("Received request to patch single step.");
            patch_singlestep(ENABLE);
            break;
        }
        case UNPATCH_SINGLESTEP:
        {
            LOG_DEBUG("Received request to restore single step.");
            patch_singlestep(DISABLE);
            break;
        }
        default:
        {
            error = ENOTSUP;
            break;
        }
    }
    return error;
}
