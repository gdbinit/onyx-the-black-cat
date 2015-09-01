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
 * kernel_info.c
 *
 * Source file with functions related to read /mach_kernel from filesystem
 * and solve kernel symbols
 *
 */

#include "kernel_info.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#include "proc.h"
#include "idt.h"
#include "sysent.h"

#define MACH_KERNEL         "/mach_kernel"      // location of kernel in filesystem
#define HEADER_SIZE         PAGE_SIZE_64*2      // amount of mach-o header to read

static char *kernel_paths[] = {
    "/mach_kernel",
    "/System/Library/Kernels/kernel",
    "/System/Library/Kernels/kernel.development",
    "/System/Library/Kernels/kernel.debug"
};

// local prototypes
static kern_return_t get_kernel_mach_header(void *buffer, vnode_t kernel_vnode, struct kernel_info *kinfo);
static kern_return_t process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo);
static kern_return_t get_kernel_linkedit(vnode_t kernel_vnode, struct kernel_info *kinfo);
static void get_running_text_address(struct kernel_info *kinfo);
static kern_return_t get_and_process_kernel_image(vnode_t kernel_vnode, struct kernel_info *kinfo);
static int is_current_kernel(void *kernel_header, mach_vm_address_t kernel_base);
static uint64_t * get_uuid(void *mach_header);

# pragma mark Exported functions

/*
 * entrypoint function to read necessary information from running kernel and kernel at disk
 * such as kaslr slide, linkedit location
 * the reads from disk are implemented using the available KPI VFS functions
 */
kern_return_t
init_kernel_info(struct kernel_info *kinfo, mach_vm_address_t kernel_base)
{
    kern_return_t error = 0;
    
    /* lookup vnode for the kernel image file */
    vnode_t kernel_vnode = NULLVP;
    vfs_context_t myvfs_ctx = vfs_context_create(NULL);
    if (myvfs_ctx == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }

    void *kernel_header = _MALLOC(HEADER_SIZE, M_TEMP, M_ZERO);
    if (kernel_header == NULL)
    {
        LOG_ERROR("Can't allocate memory.");
        vfs_context_rele(myvfs_ctx);
        return KERN_FAILURE;
    }

    int found_kernel = 0;
    for(int i = 0; i < sizeof(kernel_paths) / sizeof(*kernel_paths); i++) {
        
        if (vnode_lookup(kernel_paths[i], 0, &kernel_vnode, myvfs_ctx) == 0)
        {
            if (get_kernel_mach_header(kernel_header, kernel_vnode, kinfo) == KERN_SUCCESS)
            {
                if(!is_current_kernel(kernel_header, kernel_base))
                {
                    vnode_put(kernel_vnode);
                }
                else
                {
                    LOG_DEBUG("Found current kernel path: %s", kernel_paths[i]);
                    found_kernel = 1;
                    break;
                }
            }
        }
    }
    
    if (found_kernel == 0)
    {
        LOG_ERROR("Couldn't find kernel file image.");
        goto failure;
    }
    
    // process kernel header from filesystem
    error = process_kernel_mach_header(kernel_header, kinfo);
    if (error)
    {
        goto failure;
    }
    // compute kaslr slide
    get_running_text_address(kinfo);
    kinfo->kaslr_slide = kinfo->running_text_addr - kinfo->disk_text_addr;
    LOG_DEBUG("kernel aslr slide is 0x%llx", kinfo->kaslr_slide);
    // we know the location of linkedit and offsets into symbols and their strings
    // now we need to read linkedit into a buffer so we can process it later
    // __LINKEDIT total size is around 1MB
    // we should free this buffer later when we don't need anymore to solve symbols
    kinfo->linkedit_buf = _MALLOC(kinfo->linkedit_size, M_TEMP, M_ZERO);
    if (kinfo->linkedit_buf == NULL)
    {
        LOG_ERROR("Could not allocate enough memory for __LINKEDIT segment");
        _FREE(kernel_header, M_TEMP);
        return KERN_FAILURE;
    }
    // read linkedit from filesystem
    error = get_kernel_linkedit(kernel_vnode, kinfo);
    if (error)
    {
        goto failure;
    }

success:
    _FREE(kernel_header, M_TEMP);
    vfs_context_rele(myvfs_ctx);
    // drop the iocount due to vnode_lookup()
    // we must do this else machine will block on shutdown/reboot
    vnode_put(kernel_vnode);
    return KERN_SUCCESS;
failure:
    LOG_ERROR("Something failed at %s", __FUNCTION__);
    if (kinfo->linkedit_buf != NULL)
    {
        _FREE(kinfo->linkedit_buf, M_TEMP);
    }
    _FREE(kernel_header, M_TEMP);
    vfs_context_rele(myvfs_ctx);
    vnode_put(kernel_vnode);
    return KERN_FAILURE;
}

/*
 * cleanup the kernel info buffer to avoid memory leak.
 * there's nothing else to cleanup here, for now
 */
kern_return_t
cleanup_kernel_info(struct kernel_info *kinfo)
{
    if (kinfo->linkedit_buf != NULL)
    {
        _FREE(kinfo->linkedit_buf, M_TEMP);
    }
    return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
mach_vm_address_t
solve_kernel_symbol(struct kernel_info *kinfo, char *symbol_to_solve)
{
    if (kinfo == NULL || kinfo->linkedit_buf == NULL)
    {
        return 0;
    }

    // symbols and strings offsets into LINKEDIT
    // we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
    // subtract the base of LINKEDIT to fix the value into our buffer
    uint64_t symbol_off = kinfo->symboltable_fileoff - (kinfo->linkedit_fileoff - kinfo->fat_offset);
    if (symbol_off > kinfo->symboltable_fileoff)
    {
        return 0;
    }
    uint64_t string_off = kinfo->stringtable_fileoff - (kinfo->linkedit_fileoff - kinfo->fat_offset);
    if (string_off > kinfo->stringtable_fileoff)
    {
        return 0;
    }
    
    if (sizeof(void*) == 4)
    {
        struct nlist *nlist = NULL;
        // search for the symbol and get its location if found
        for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
        {
            // get the pointer to the symbol entry and extract its symbol string
            nlist = (struct nlist*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist));
            char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
            // find if symbol matches
            if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)+1) == 0)
            {
                LOG_DEBUG("Found symbol %s at 0x%llx (non-aslr 0x%x)", symbol_to_solve, nlist->n_value + kinfo->kaslr_slide, nlist->n_value);
                // the symbols values are without kernel ASLR so we need to add it
                return (nlist->n_value + kinfo->kaslr_slide);
            }
        }
    }
    else if (sizeof(void*) == 8)
    {
        struct nlist_64 *nlist64 = NULL;
        // search for the symbol and get its location if found
        for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
        {
            // get the pointer to the symbol entry and extract its symbol string
            nlist64 = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
            char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist64->n_un.n_strx);
            // find if symbol matches
            if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)+1) == 0)
            {
                LOG_DEBUG("Found symbol %s at 0x%llx (non-aslr 0x%llx)", symbol_to_solve, nlist64->n_value + kinfo->kaslr_slide, nlist64->n_value);
                // the symbols values are without kernel ASLR so we need to add it
                return (nlist64->n_value + kinfo->kaslr_slide);
            }
        }
    }
    // failure
    return 0;
}

/*
 * return the address of the symbol after the one in the parameter
 * this is a cheap/not very reliable trick to find out the size of a given symbol
 * cheap because we might have static functions between the two symbols, for example
 */
mach_vm_address_t
solve_next_kernel_symbol(const struct kernel_info *kinfo, const char *symbol)
{
    struct nlist_64 *nlist = NULL;
    
    if (kinfo == NULL || kinfo->linkedit_buf == NULL)
    {
        return 0;
    }

    mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
    mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;

    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        if (strncmp(symbol, symbol_string, strlen(symbol)+1) == 0)
        {
            // lookup the next symbol
            nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + (i+1) * sizeof(struct nlist_64));
            symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
            LOG_DEBUG("Found next symbol %s at 0x%llx (%s)", symbol, nlist->n_value, symbol_string);
            return (nlist->n_value + kinfo->kaslr_slide);
        }
    }
    // failure
    return 0;
}

#pragma mark Internal helper functions

/*
 * retrieve the first page of kernel binary at disk into a buffer
 * version that uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
 */
static kern_return_t
get_kernel_mach_header(void *buffer, vnode_t kernel_vnode, struct kernel_info *kinfo)
{
    int error = 0;
    uio_t uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL)
    {
        LOG_ERROR("uio_create returned null!");
        return KERN_FAILURE;
    }
    // imitate the kernel and read a single page from the header
    error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), HEADER_SIZE);
    if (error)
    {
        LOG_ERROR("uio_addiov returned error!");
        return error;
    }
    
    vfs_context_t myvfs_ctx = vfs_context_create(NULL);
    if (myvfs_ctx == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }

    // read kernel vnode into the buffer
    error = VNOP_READ(kernel_vnode, uio, 0, myvfs_ctx);
    if (error)
    {
        LOG_ERROR("VNOP_READ failed with error: %d.", error);
        vfs_context_rele(myvfs_ctx);
        return error;
    }
    else if (uio_resid(uio))
    {
        vfs_context_rele(myvfs_ctx);
        return EINVAL;
    }
    
    // process the header
    uint32_t magic = *(uint32_t*)buffer;
    if (magic == FAT_CIGAM)
    {
        LOG_DEBUG("Target is fat %d!", (int)sizeof(void*));
        struct fat_header *fh = (struct fat_header*)buffer;
        struct fat_arch *fa = (struct fat_arch*)(buffer + sizeof(struct fat_header));
        uint32_t file_offset = 0;
        for (uint32_t i = 0; i < ntohl(fh->nfat_arch); i++)
        {
            LOG_DEBUG("Process arch %d", ntohl(fa->cputype));
            if (sizeof(void*) == 8 && ntohl(fa->cputype) == CPU_TYPE_X86_64)
            {
                file_offset = ntohl(fa->offset);
                break;
            }
            else if (sizeof(void*) == 4 && ntohl(fa->cputype) == CPU_TYPE_X86)
            {
                LOG_DEBUG("Reading 32bits kernel");
                file_offset = ntohl(fa->offset);
                break;
            }
            fa++;
        }
        // read again
        /* XXX: add error checking here! */
        uio = uio_create(1, file_offset, UIO_SYSSPACE, UIO_READ);
        error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), HEADER_SIZE);
        error = VNOP_READ(kernel_vnode, uio, 0, myvfs_ctx);
        kinfo->fat_offset = file_offset;
    }
    else
    {
        kinfo->fat_offset = 0;
    }

    vfs_context_rele(myvfs_ctx);
    return KERN_SUCCESS;
}

/*
 * retrieve the whole linkedit segment into target buffer from kernel binary at disk
 * we keep this buffer until we don't need to solve symbols anymore
 */
static kern_return_t
get_kernel_linkedit(vnode_t kernel_vnode, struct kernel_info *kinfo)
{
    int error = 0;
    uio_t uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL)
    {
        return KERN_FAILURE;
    }
    error = uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size);
    if (error)
    {
        return error;
    }
    
    vfs_context_t myvfs_ctx = vfs_context_create(NULL);
    if (myvfs_ctx == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }

    error = VNOP_READ(kernel_vnode, uio, 0, myvfs_ctx);
    
    if (error)
    {
        vfs_context_rele(myvfs_ctx);
        return error;
    }
    else if (uio_resid(uio))
    {
        vfs_context_rele(myvfs_ctx);
        return EINVAL;
    }
    
    vfs_context_rele(myvfs_ctx);
    return KERN_SUCCESS;
}

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * stored at our kernel_info structure
 */
static kern_return_t
process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo)
{
    struct mach_header *mh = (struct mach_header*)kernel_header;
    int header_size = sizeof(struct mach_header);
    switch (mh->magic) {
        case MH_MAGIC:
            break;
        case MH_MAGIC_64:
            header_size = sizeof(struct mach_header_64);
            break;
        default:
            LOG_ERROR("Header buffer does not contain valid Mach-O binary!");
            return KERN_FAILURE;
    }

    struct load_command *load_cmd = NULL;
    // point to the first load command
    char *load_cmd_addr = (char*)kernel_header + header_size;
    // iterate over all load cmds and retrieve required info to solve symbols
    // __LINKEDIT location and symbol/string table location
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT)
        {
            struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                kinfo->disk_text_addr = seg_cmd->vmaddr;
                char *section_addr = load_cmd_addr + sizeof(struct segment_command);
                struct section *section_cmd = NULL;
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    section_cmd = (struct section*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        kinfo->text_size = section_cmd->size;
                        break;
                    }
                    section_addr += sizeof(struct section);
                }
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
            }
        }
        else if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            // use this one to retrieve the original vm address of __TEXT so we can compute kernel aslr slide
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                kinfo->disk_text_addr = seg_cmd->vmaddr;
                // lookup the __text section - we want the size which can be retrieve here or from the running version
                char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                struct section_64 *section_cmd = NULL;
                // iterate thru all sections
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    section_cmd = (struct section_64*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        kinfo->text_size = section_cmd->size;
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
            }
        }
        // table information available at LC_SYMTAB command
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
            kinfo->symboltable_fileoff    = symtab_cmd->symoff;
            kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
            kinfo->stringtable_fileoff    = symtab_cmd->stroff;
            kinfo->stringtable_size       = symtab_cmd->strsize;
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    // add the fat offset to linkedit fileoffset
    kinfo->linkedit_fileoff += kinfo->fat_offset;
    return KERN_SUCCESS;
}

/*
 * retrieve the __TEXT address of current loaded kernel so we can compute the KASLR slide
 * also the size of __text 
 */
static void
get_running_text_address(struct kernel_info *kinfo)
{
    // retrieves the address of the IDT
    mach_vm_address_t idt_address = 0;
    get_addr_idt(&idt_address);
    // calculate the address of the int80 handler
    mach_vm_address_t int80_address = calculate_int80address(idt_address);
    // search backwards for the kernel base address (mach-o header)
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    if (kernel_base != 0)
    {
        // get the vm address of __TEXT segment
        struct mach_header *mh = (struct mach_header*)kernel_base;
        int header_size = 0;
        if (mh->magic == MH_MAGIC) header_size = sizeof(struct mach_header);
        else if (mh->magic == MH_MAGIC_64) header_size = sizeof(struct mach_header_64);
            
        struct load_command *load_cmd = NULL;
        char *load_cmd_addr = (char*)kernel_base + header_size;
        for (uint32_t i = 0; i < mh->ncmds; i++)
        {
            load_cmd = (struct load_command*)load_cmd_addr;
            if (load_cmd->cmd == LC_SEGMENT)
            {
                struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                {
                    kinfo->running_text_addr = seg_cmd->vmaddr;
                    // FIXME
                    kinfo->mh = (struct mach_header_64*)kernel_base;
                }
            }
            else if (load_cmd->cmd == LC_SEGMENT_64)
            {
                struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                {
                    kinfo->running_text_addr = seg_cmd->vmaddr;
                    kinfo->mh = (struct mach_header_64*)kernel_base;
                    break;
                }
            }
            load_cmd_addr += load_cmd->cmdsize;
        }
    }
}

static uint64_t *
get_uuid(void *mach_header)
{
    struct mach_header *mh = (struct mach_header*)mach_header;
    int header_size = 0;
    if (mh->magic == MH_MAGIC)
    {
        header_size = sizeof(struct mach_header);
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        header_size = sizeof(struct mach_header_64);
    }
    
    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)mach_header + header_size;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_UUID)
        {
            return (uint64_t *)((struct uuid_command *)load_cmd)->uuid;
        }
        
        load_cmd_addr += load_cmd->cmdsize;
    }
    
    return NULL;
}

static int
is_current_kernel(void *kernel_header, mach_vm_address_t kernel_base)
{
    uint64_t *uuid1 = get_uuid(kernel_header);
    uint64_t *uuid2 = get_uuid((void*)kernel_base);
    
    if(!uuid1 || !uuid2)
    {
        return 0;
    }
    
    return uuid1[0] == uuid2[0] && uuid1[1] == uuid2[1];
}

