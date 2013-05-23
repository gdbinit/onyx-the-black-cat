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
 * cpu_protections.c
 *
 * Functions related to kernel memory protections
 *
 */

#include "cpu_protections.h"

/*
 * disable the Write Protection bit in CR0 register
 * so we can modify kernel code
 */
kern_return_t
disable_wp(void)
{
	uintptr_t cr0;
	// retrieve current value
	cr0 = get_cr0();
	// remove the WP bit
	cr0 = cr0 & ~CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) == 0) return KERN_SUCCESS;
    else return KERN_FAILURE;
}

/*
 * enable the Write Protection bit in CR0 register
 */
kern_return_t
enable_wp(void)
{
	uintptr_t cr0;
	// retrieve current value
	cr0 = get_cr0();
	// add the WP bit
	cr0 = cr0 | CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) != 0) return KERN_SUCCESS;
    else return KERN_FAILURE;
}

/*
 * check if WP is set or not
 * 0 - it's set
 * 1 - not set
 */
uint8_t
verify_wp(void)
{
    uintptr_t cr0;
    cr0 = get_cr0();
    if (cr0 & CR0_WP) return 0;
    else return 1;
}

void
enable_kernel_write(void)
{
    disable_interrupts();
    disable_wp();
}

void
disable_kernel_write(void)
{
    enable_wp();
    enable_interrupts();
}
