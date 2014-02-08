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
 * shared_data.h
 *
 */

// this file should be shared with the userland client that will connect
// to the kernel control socket

#ifndef onyx_shared_data_h
#define onyx_shared_data_h

#define BUNDLE_ID   "put.as.onyx_the_black_cat"
#define MAGIC       "SpecialisRevelio"
// the supported commands
#define PATCH_TASK_FOR_PID     0x0
#define UNPATCH_TASK_FOR_PID   0x1
#define ANTI_PTRACE_ON         0x2
#define ANTI_PTRACE_OFF        0x3
#define ANTI_SYSCTL_ON         0x4
#define ANTI_SYSCTL_OFF        0x5
#define ANTI_KAUTH_ON          0x6
#define ANTI_KAUTH_OFF         0x7
#define PATCH_RESUME_FLAG      0x8
#define UNPATCH_RESUME_FLAG    0x9
#define PATCH_SINGLESTEP       0xa
#define UNPATCH_SINGLESTEP     0xb

#endif
