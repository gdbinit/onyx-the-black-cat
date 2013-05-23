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
 * sysent.h
 *
 */

#ifndef onyx_sysent_h
#define onyx_sysent_h
#include "sysproto.h"
#include "syscall.h"
#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <string.h>
#include <mach-o/loader.h>
#include <libkern/libkern.h>

/* Function prototypes */
int our_getxattr(struct proc *, struct getxattr_args *, int *);
int our_fgetxattr(struct proc *, struct fgetxattr_args *, int *);
int our_setxattr(struct proc *, struct setxattr_args *, int *);
int our_fsetxattr(struct proc *, struct fsetxattr_args *, int *);
int our_removexattr(struct proc *, struct removexattr_args *, int *l);
int our_fremovexattr(struct proc *, struct fremovexattr_args *, int *);
int our_listxattr(struct proc *, struct listxattr_args *, int *);
int our_flistxattr(struct proc *, struct flistxattr_args *, int *);
int our_gethostuuid (struct proc *, struct gethostuuid_args *, int *);

typedef int getxattr_func_t (struct proc *, struct getxattr_args *, int *);
typedef int fgetxattr_func_t (struct proc *, struct fgetxattr_args *, int *);
typedef int setxattr_func_t (struct proc *, struct setxattr_args *, int *);
typedef int fsetxattr_func_t (struct proc *, struct fsetxattr_args *, int *);
typedef int removexattr_func_t (struct proc *, struct removexattr_args *, int *);
typedef int fremovexattr_func_t (struct proc *, struct fremovexattr_args *, int *);
typedef int listxattr_func_t (struct proc *, struct listxattr_args *, int *);
typedef int flistxattr_func_t (struct proc *, struct flistxattr_args *, int *);
typedef int gethostuuid_func_t (struct proc *, struct gethostuuid_args *, int *);

kern_return_t find_sysent(void);
kern_return_t cleanup_sysent(void);
mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);

#endif


