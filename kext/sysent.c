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
 * sysent.c
 *
 */

#include "sysent.h"
#include "cpu_protections.h"
#include "my_data_definitions.h"
#include "idt.h"

// global vars
struct sysent *g_sysent;

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

extern int (*real_ptrace)(struct proc *, struct ptrace_args *, int *);
extern int (*real_sysctl)(struct proc *, struct __sysctl_args *, int *);

// local functions
static uint8_t process_header(const mach_vm_address_t target_address, uint64_t *data_address, uint64_t *data_size);
static void* bruteforce_sysent(void);

#pragma mark Externally available functions

/*
 * external available function to find sysent table
 * if it fails then kext loading will have to fail
 */
kern_return_t
find_sysent(void)
{
    LOG_DEBUG("[DEBUG] Finding sysent table...\n");
    // retrieve sysent address
    g_sysent = (struct sysent*)bruteforce_sysent();
    // if we can't find it return a kernel module failure
    if (g_sysent == NULL)
    {
        LOG_MSG("[ERROR] Cannot find sysent table\n");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * function to remove all installed sysent hook, if there are any active
 */
kern_return_t
cleanup_sysent(void)
{
    disable_wp();
    if (real_ptrace != NULL && g_sysent[SYS_ptrace].sy_call != (sy_call_t *)real_ptrace)
    {
        g_sysent[SYS_ptrace].sy_call = (sy_call_t *)real_ptrace;
    }
    if (real_sysctl != NULL && g_sysent[SYS___sysctl].sy_call != (sy_call_t *)real_sysctl)
    {
        g_sysent[SYS___sysctl].sy_call = (sy_call_t *)real_sysctl;
    }
    enable_wp();
    return KERN_SUCCESS;
}

/*
 * calculate the address of the kernel int80 handler
 * using the IDT array
 */
mach_vm_address_t
calculate_int80address(const mach_vm_address_t idt_address)
{
  	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor;
	mach_vm_address_t int80_address;
    // we need to compute the address, it's not direct
    // extract the stub address
#if __LP64__
    // retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
    uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low);
#else
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    int80_address = (mach_vm_address_t)(int80_descriptor->offset_middle << 16) + int80_descriptor->offset_low;
#endif
	LOG_DEBUG("[DEBUG] Address of interrupt 80 stub is %llu\n", int80_address);
    return int80_address;
}

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
mach_vm_address_t
find_kernel_base(const mach_vm_address_t int80_address)
{
    mach_vm_address_t temp_address = int80_address;
#if __LP64__
    struct segment_command_64 *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)(temp_address) == MH_MAGIC_64)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
                LOG_DEBUG("[DEBUG] Found kernel mach-o header address at %p\n", (void*)(temp_address));
                return temp_address;
            }
        }
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
#else
    struct segment_command *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)((uint32_t)temp_address) == MH_MAGIC)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command*)((uint32_t)temp_address + sizeof(struct mach_header));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
                LOG_DEBUG("[DEBUG] Found kernel mach-o header address at %p\n", (void*)((uint32_t)temp_address));
                return (mach_vm_address_t)temp_address;
            }
        }
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
#endif
    return 0;
}

#pragma mark Local functions

/*
 * brute force search sysent
 * this method works in all versions
 * returns a pointer to the sysent structure
 * Note: 32/64 bits compatible
 */
static void *
bruteforce_sysent(void)
{
    // retrieves the address of the IDT
    mach_vm_address_t idt_address = 0;
    get_addr_idt(&idt_address);
    printf("[DEBUG] IDT Address is %llx\n", idt_address);
    // calculate the address of the int80 handler
    mach_vm_address_t int80_address = calculate_int80address(idt_address);
    // search backwards for the kernel base address (mach-o header)
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    uint64_t data_address = 0;
    uint64_t data_size = 0;
    // search for the __DATA segment
    process_header(kernel_base, &data_address, &data_size);
    uint64_t data_limit = data_address + data_size;
    // bruteforce search for sysent in __DATA segment
    while (data_address <= data_limit)
    {
        struct sysent *table = (struct sysent*)(data_address);
        if(table[SYS_exit].sy_narg      == 1 &&
           table[SYS_fork].sy_narg      == 0 &&
           table[SYS_read].sy_narg      == 3 &&
           table[SYS_wait4].sy_narg     == 4 &&
           table[SYS_ptrace].sy_narg    == 4 &&
           table[SYS_getxattr].sy_narg  == 6 &&
           table[SYS_listxattr].sy_narg == 4 &&
           table[SYS_recvmsg].sy_narg   == 3 )
        {
            LOG_DEBUG("[DEBUG] exit() address is %p\n", (void*)table[SYS_exit].sy_call);
            return table;
        }
        data_address++;
    }
    return NULL;
}

/* 
 * process target kernel module header and retrieve some info we need
 * more specifically the __DATA segment
 */
static uint8_t
process_header(const mach_vm_address_t target_address, uint64_t *data_address, uint64_t *data_size)
{
    // verify if it's a valid mach-o binary
    struct mach_header *mh = (struct mach_header*)target_address;
    int header_size = 0;
    if (mh->magic == MH_MAGIC)
    {
        header_size = sizeof(struct mach_header);
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        header_size = sizeof(struct mach_header_64);
    }
    // error
    else
    {
        LOG_MSG("[ERROR] Not a valid mach-o binary address passed to %s\n", __FUNCTION__);
        return 1;
    }
    
    // find the last command offset
    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)target_address + header_size;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        switch (load_cmd->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)load_cmd;
                if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    *data_address = segmentCommand->vmaddr;
                    *data_size    = segmentCommand->vmsize;
                    LOG_DEBUG("[DEBUG] Found __DATA segment at %p!\n", (void*)*data_address);
                }
                break;
            }
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *segmentCommand = (struct segment_command_64 *)load_cmd;
                if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    *data_address = segmentCommand->vmaddr;
                    *data_size    = segmentCommand->vmsize;
                    LOG_DEBUG("[DEBUG] Found __DATA segment at %p!\n", (void*)*data_address);
                }
                break;
            }
        }
        // advance to next command
        load_cmd_addr += load_cmd->cmdsize;
    }
    return 0;
}

