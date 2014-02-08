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
 * disasm_utils.c
 *
 * Functions that use diStorm disassembler to find whatever info we need
 *
 */

#include "disasm_utils.h"

#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <sys/systm.h>
#include <mach/mach_types.h>

#include "distorm.h"
#include "mnemonics.h"
#include "utlist.h"

#define MAX_INSTRUCTIONS 8192
#define RF_FLAG_32BITS 0xFFFE8DFF
#define RF_FLAG_64BITS 0x0FFFFFFFFFFFE8DFF

// external global vars
extern struct kernel_info g_kernel_info;

// local functions prototypes
static kern_return_t disasm_jumps(mach_vm_address_t start, struct patch_location **patch_locations);

/*
 * find the locations where we need to patch the resume flag
 * this code is a bit ugly :-]
 * the value we are looking for is 0xFFFE8DFF and 0x0FFFFFFFFFFFE8DFF
 * it is used in machine_thread_set_state() and two other static functions: set_thread_state32 and set_thread_state64
 * two find the static functions we can follow all the jumps inside machine_thread_set_state()
 * and then disassemble each looking for the same value
 *
 * this implementation is ugly because in some versions there is recursion - the static functions are next
 * to machine_thread_set_state() and its fixed disassembly size runs into them
 * 
 * code that needs to be patched:
 * @ xnu/osfmk/i386/pcb.c
 kern_return_t
 machine_thread_set_state(
 thread_t thr_act,
 thread_flavor_t flavor,
 thread_state_t tstate,
 mach_msg_type_number_t count)
 {
 (...)
 saved_state->efl = (state->efl & ~EFL_USER_CLEAR) | EFL_USER_SET;
 (...)
 saved_state->isf.rflags = (state->isf.rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
 (...)
 }
 
 and the same inside inside set_thread_state32() and set_thread_state64():
 saved_state->efl = (ts->eflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
 saved_state->isf.rflags = (ts->rflags & ~EFL_USER_CLEAR) | EFL_USER_SET;
 */
kern_return_t
find_resume_flag(mach_vm_address_t start, struct patch_location **patch_locations)
{
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
        LOG_ERROR("Decoded instructions allocation failed!");
        return -1;
    }
    
	_DecodeResult res = 0;
    _CodeInfo ci = {0} ;
#if __LP64__
    ci.dt = Decode64Bits;
#else
    ci.dt = Decode32Bits;
#endif
    ci.features = DF_NONE;
    ci.codeLen = 4096;
    ci.code = (unsigned char*)start;
    ci.codeOffset = start;
    mach_vm_address_t next;
    uint32_t decodedInstructionsCount = 0;
    // linked list to store all jump references we will disassembler on 2nd pass
    struct jumps
    {
        mach_vm_address_t address;
        struct jumps *next;
    };
    struct jumps *jump_locations = NULL;
    
    // first pass - find the flags being used inside machine_thread_set_state()
    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
            LOG_ERROR("Distorm failed to disassemble!");
            goto failure;
        }

        for (int i = 0; i < decodedInstructionsCount; i++)
        {            
            if (decodedInstructions[i].opcode == I_AND &&
                decodedInstructions[i].ops[1].type == O_IMM &&
                decodedInstructions[i].imm.dword == RF_FLAG_32BITS)
            {
                LOG_DEBUG("Found AND at 0x%llx %x", decodedInstructions[i].addr, decodedInstructions[i].imm.dword);
                struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
                new->address = decodedInstructions[i].addr;
                new->size = decodedInstructions[i].size;
                memcpy(new->orig_bytes, new->address, new->size);
                LL_PREPEND(*patch_locations, new);
            }
            else if (decodedInstructions[i].opcode == I_MOV &&
                     decodedInstructions[i].ops[1].type == O_IMM &&
                     decodedInstructions[i].imm.qword == RF_FLAG_64BITS)
            {
                struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
                new->address = decodedInstructions[i].addr;
                new->size = decodedInstructions[i].size;
                memcpy(new->orig_bytes, new->address, new->size);
                LL_PREPEND(*patch_locations, new);
                LOG_DEBUG("Found MOV at 0x%llx %llx", decodedInstructions[i].addr, decodedInstructions[i].imm.qword);
            }
            // find jumps to locate the other functions that contain the value we want to modify
            else if (decodedInstructions[i].opcode == I_JMP &&
                     decodedInstructions[i].ops[0].type == O_PC)
            {
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                struct jumps *new = _MALLOC(sizeof(struct jumps), M_TEMP, M_WAITOK);
                new->address = rip_address;
                LL_PREPEND(jump_locations, new);
                LOG_DEBUG("0x%llx JMP %d to 0x%llx", decodedInstructions[i].addr, decodedInstructions[i].ops[0].type, rip_address);
            }
        }
        
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
    // second pass - cycle thru the jumps and disassemble each
    struct jumps *jumps_tmp = NULL;
    LL_FOREACH(jump_locations, jumps_tmp)
    {
        disasm_jumps(jumps_tmp->address, patch_locations);
    }
    
#if DEBUG
    struct patch_location *tmp = NULL;
    LL_FOREACH(*patch_locations, tmp)
    {
        LOG_DEBUG("patch location: 0x%llx", tmp->address);
    }
#endif
    
end:
    _FREE(decodedInstructions, M_TEMP);
    struct jumps *eljmp, *tmpjmp;
    LL_FOREACH_SAFE(jump_locations, eljmp, tmpjmp)
    {
        _FREE(eljmp, M_TEMP);
    }
    return KERN_SUCCESS;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return KERN_FAILURE;
}

/*
 * function to lookup address where we need to patch task_for_pid()
 * so we can restore ability to get kernel task port from userland
 * code that needs to be patched:
 * @ xnu/bsd/vm/vm_unix.c
 kern_return_t
 task_for_pid(struct task_for_pid_args *args)
 {
  (...)
    // Always check if pid == 0
    if (pid == 0) {
        (void ) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
        AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
        return(KERN_FAILURE);
    }
  (...)
 }
 */
kern_return_t
find_task_for_pid(mach_vm_address_t start, mach_vm_address_t symbol_addr, struct patch_location *topatch)
{
    kern_return_t ret = KERN_FAILURE;
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
        LOG_ERROR("Decoded instructions allocation failed!");
        return ret;
    }
    
	_DecodeResult res = 0;
    _CodeInfo ci = {0} ;
#if __LP64__
    ci.dt = Decode64Bits;
#else
    ci.dt = Decode32Bits;
#endif
    ci.features = DF_NONE;
    ci.codeLen = 4096;
    ci.code = (unsigned char*)start;
    ci.codeOffset = start;
    mach_vm_address_t next;
    uint32_t decodedInstructionsCount = 0;

    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
            LOG_ERROR("Distorm failed to disassemble!");
            goto end;
        }
        
        // XXX: this is ugly but does the job :X
        for (uint32_t i = 0; i < decodedInstructionsCount; i++)
        {
            // find call to audit_arg_mach_port1()
            if (decodedInstructions[i].opcode == I_CALL &&
                decodedInstructions[i].ops[0].type == O_PC)
            {
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                // found location of call to audit_arg_mach_port1()
                if (rip_address == symbol_addr)
                {
                    LOG_DEBUG("Found call to audit_arg_mach_port1");
                    // try to find the test and conditional jump in the next instructions
                    for (uint32_t x = i; x < i + 10 && x < decodedInstructionsCount; x++)
                    {
                        if (decodedInstructions[x].opcode == I_TEST)
                        {
                            LOG_DEBUG("Found test at %p", (void*)decodedInstructions[x].addr);
                            for (uint32_t z = x; z < x + 10 && z < decodedInstructionsCount; z++)
                            {
                                if (decodedInstructions[z].opcode == I_JZ)
                                {
                                    LOG_DEBUG("Found conditional jump at %p", (void*)decodedInstructions[z].addr);
                                    topatch->address = decodedInstructions[z].addr;
                                    topatch->size = decodedInstructions[z].size;
                                    memcpy(topatch->orig_bytes, topatch->address, topatch->size);
                                    topatch->jmp = 0;
                                    ret = KERN_SUCCESS;
                                    goto end;
                                }
                                else if (decodedInstructions[z].opcode == I_JNZ)
                                {
                                    LOG_DEBUG("Found conditional jump at %p", (void*)decodedInstructions[z].addr);
                                    topatch->address = decodedInstructions[z].addr;
                                    topatch->size = decodedInstructions[z].size;
                                    memcpy(topatch->orig_bytes, topatch->address, topatch->size);
                                    topatch->jmp = 1;
                                    ret = KERN_SUCCESS;
                                    goto end;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
    
end:
    _FREE(decodedInstructions, M_TEMP);
    return ret;
}

/*
 * function to lookup address where we need to patch kauth in ptrace()
 * so we can patch anti-debug described in Apple Technical Note TN2127
 * the code that needs to be patched is the following:
 * @ xnu/bsd/kern/mach_process.c
 int
 ptrace(struct proc *p, struct ptrace_args *uap, int32_t *retval)
 {
   (...)
    if (uap->req == PT_ATTACH) {
    int		err;
 
        if ( kauth_authorize_process(proc_ucred(p), KAUTH_PROCESS_CANTRACE, t, (uintptr_t)&err, 0, 0) == 0 ) {
            (...)
        }
    }
 }

 */
kern_return_t
find_kauth(mach_vm_address_t start, mach_vm_address_t symbol_addr, struct patch_location *topatch)
{
    kern_return_t ret = KERN_FAILURE;
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
        LOG_ERROR("Decoded instructions allocation failed!");
        return ret;
    }
    
	_DecodeResult res = 0;
    _CodeInfo ci = {0} ;
#if __LP64__
    ci.dt = Decode64Bits;
#else
    ci.dt = Decode32Bits;
#endif
    ci.features = DF_NONE;
    ci.codeLen = 4096;
    ci.code = (unsigned char*)start;
    ci.codeOffset = start;
    mach_vm_address_t next;
    uint32_t decodedInstructionsCount = 0;
    
    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
            LOG_ERROR("Distorm failed to disassemble!");
            goto end;
        }
        
        // XXX: this is ugly but does the job :X
        for (int i = 0; i < decodedInstructionsCount; i++)
        {
            // find call to kauth_authorize_process()
            if (decodedInstructions[i].opcode == I_CALL &&
                decodedInstructions[i].ops[0].type == O_PC)
            {
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                // found location of call to kauth_authorize_process()
                if (rip_address == symbol_addr)
                {
                    LOG_DEBUG("Found call to kauth_authorize_process");
                    // try to find the test and conditional jump in the next instructions
                    for (uint32_t x = i; x < i + 10 && x < decodedInstructionsCount; x++)
                    {
                        if (decodedInstructions[x].opcode == I_TEST)
                        {
                            LOG_DEBUG("Found test at %p", (void*)decodedInstructions[x].addr);
                            for (uint32_t z = x; z < x + 10 && z < decodedInstructionsCount; z++)
                            {
                                if (decodedInstructions[z].opcode == I_JNZ)
                                {
                                    LOG_DEBUG("Found conditional jump at %p", (void*)decodedInstructions[z].addr);
                                    topatch->address = decodedInstructions[z].addr;
                                    topatch->size = decodedInstructions[z].size;
                                    memcpy(topatch->orig_bytes, topatch->address, topatch->size);
                                    topatch->jmp = 1;
                                    ret = KERN_SUCCESS;
                                    goto end;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
    
end:
    _FREE(decodedInstructions, M_TEMP);
    return ret;
}

#pragma mark Local auxiliary functions

/*
 * auxiliary function to disassemble the jumps from resume flag
 */
static kern_return_t
disasm_jumps(mach_vm_address_t start, struct patch_location **patch_locations)
{
    LOG_DEBUG("Executing %s starting at address %llx", __FUNCTION__, start);
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
        LOG_ERROR("Decoded instructions allocation failed!");
        return -1;
    }
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;
    _CodeInfo ci = {0} ;
#if __LP64__
    ci.dt = Decode64Bits;
#else
    ci.dt = Decode32Bits;
#endif
    ci.features = DF_NONE;
    ci.codeLen = 512;
    ci.code = (unsigned char*)start;
    ci.codeOffset = start;
    mach_vm_address_t next;
    
    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
            LOG_ERROR("Distorm failed to disassemble!");
            goto failure;
        }
        
        for (int i = 0; i < decodedInstructionsCount; i++)
        {
            if (decodedInstructions[i].opcode == I_AND &&
                decodedInstructions[i].ops[1].type == O_IMM &&
                decodedInstructions[i].imm.dword == RF_FLAG_32BITS)
            {
                LOG_DEBUG("Found AND at 0x%llx %x", decodedInstructions[i].addr, decodedInstructions[i].imm.dword);
                // test if value already exists on the list
                struct patch_location *tmp = NULL;
                int exists = 0;
                LL_FOREACH(*patch_locations, tmp)
                {
                    if (tmp->address == decodedInstructions[i].addr)
                    {
                        exists++;
                    }
                }
                if (!exists)
                {
                    struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
                    new->address = decodedInstructions[i].addr;
                    new->size = decodedInstructions[i].size;
                    memcpy(new->orig_bytes, new->address, new->size);
                    LL_PREPEND(*patch_locations, new);
                }
            }
            else if (decodedInstructions[i].opcode == I_MOV &&
                     decodedInstructions[i].ops[1].type == O_IMM &&
                     decodedInstructions[i].imm.qword == RF_FLAG_64BITS)
            {
                struct patch_location *tmp = NULL;
                int exists = 0;
                LL_FOREACH(*patch_locations, tmp)
                {
                    if (tmp->address == decodedInstructions[i].addr)
                    {
                        exists++;
                    }
                }
                if (!exists)
                {
                    struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
                    new->address = decodedInstructions[i].addr;
                    new->size = decodedInstructions[i].size;
                    memcpy(new->orig_bytes, new->address, new->size);
                    LL_PREPEND(*patch_locations, new);
                    LOG_DEBUG("Found MOV at 0x%llx %llx", decodedInstructions[i].addr, decodedInstructions[i].imm.qword);
                }
            }
        }
        
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
end:
    _FREE(decodedInstructions, M_TEMP);
    return KERN_SUCCESS;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return KERN_FAILURE;
}
