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
 * The userland daemon to control Onyx The Black Cat kernel extension
 *
 * main.c
 *
 * Menus code ripped from Rubilyn rootkit :-)
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/sys_domain.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>

#include "shared_data.h"

static int g_socket = -1;

#define MAXLEN 4098
#define MAXARG 512
#define MAGIC "SpecialisRevelio"

int
connect_to_kernel(void)
{
    struct sockaddr_ctl sc = {0};
    struct ctl_info ctl_info = {0};
    int ret = 0;
    
    g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (g_socket < 0)
    {
        printf("[ERROR] Failed to create socket!\n");
        exit(1);
    }
    // the control ID is dynamically generated so we must obtain sc_id using ioctl
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, BUNDLE_ID, MAX_KCTL_NAME);
    ctl_info.ctl_name[MAX_KCTL_NAME-1] = '\0';
	if (ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1)
    {
		printf("[ERROR] ioctl CTLIOCGINFO failed!\n");
		exit(1);
	}
#if DEBUG
    printf("[DEBUG] ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
#endif
    
    bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
    
    ret = connect(g_socket, (struct sockaddr*)&sc, sizeof(sc));
    if (ret)
    {
        printf("[ERROR] Connect failed!\n");
        exit(1);
    }
    return 0;
}

void
print_menu(void)
{
    printf("[Onyx The Black Cat Kernel Control]\n");
	printf("[menu]\n");
	printf("[1] enable anti-anti-ptrace\n");
	printf("[2] disable anti-anti-ptrace\n");
	printf("[3] enable sysctl anti-anti-debug\n");
	printf("[4] disable sysctl anti-anti-debug\n");
	printf("[5] patch resume flag\n");
	printf("[6] restore resume flag\n");
	printf("[7] patch task_for_pid(0)\n");
	printf("[8] restore task_for_pid()\n");
	printf("[9] patch kauth\n");
    printf("[0] restore kauth\n");
    printf("[a] activate single-step-on-branch\n");
    printf("[b] restore single-step-on-branch\n");
	printf("[h] help\n");
	printf("[q] exit\n");
}

void
execute_cmd(int cmd)
{
    char *magic = MAGIC;
    size_t magic_len = strlen(magic)+1;
    int ret = setsockopt(g_socket, SYSPROTO_CONTROL, cmd, (void*)magic, (socklen_t)magic_len);
    if (ret)
    {
        printf("[ERROR] Kernel command execution failed!\n");
    }
}

void main_menu()
{
	char str;
	do {
		printf("--> ");
        str = getchar();
        switch(str)
        {
			case '1':
                execute_cmd(ANTI_PTRACE_ON);
				break;
			case '2':
                execute_cmd(ANTI_PTRACE_OFF);
                break;
            case '3':
                execute_cmd(ANTI_SYSCTL_ON);
				break;
			case '4':
                execute_cmd(ANTI_SYSCTL_OFF);
				break;
			case '5':
                execute_cmd(PATCH_RESUME_FLAG);
				break;
			case '6':
                execute_cmd(UNPATCH_RESUME_FLAG);
				break;
			case '7':
                execute_cmd(PATCH_TASK_FOR_PID);
				break;
			case '8':
                execute_cmd(UNPATCH_TASK_FOR_PID);
				break;
			case '9':
                execute_cmd(ANTI_KAUTH_ON);
				break;
            case '0':
                execute_cmd(ANTI_KAUTH_OFF);
                break;
            case 'a':
                execute_cmd(PATCH_SINGLESTEP);
                break;
            case 'b':
                execute_cmd(UNPATCH_SINGLESTEP);
                break;
			case 'h':
				print_menu();
				break;
			case '?':
				print_menu();
				break;
			case 'q':
				exit(0);
				break;
			case 'x':
				exit(0);
				break;
			default:
				printf("Invalid selection!\n");
                break;
        }
    }
    while(getchar() != '\n');
}

int main(int argc, const char * argv[])
{
    if (connect_to_kernel())
    {
        printf("[ERROR] Can't connect to kernel control socket!\n");
        exit(1);
    }
    print_menu();
    while(1)
    {
		main_menu();
	}
	return 0;
}
