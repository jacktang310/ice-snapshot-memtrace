/* ******************************************************************************
 * Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * instrace_x86.c
 *
 * Collects a dynamic instruction trace and dumps it to a file.
 * This is an x86-specific implementation of an instruction tracing client.
 * For a simpler (and slower) arch-independent version, please see instrace_simple.c.
 *
 * Illustrates how to create generated code in a local code cache and
 * perform a lean procedure call to that generated code.
 *
 * (1) Fills a buffer and dumps the buffer when it is full.
 * (2) Inlines the buffer filling code to avoid a full context switch.
 * (3) Uses a lean procedure call for clean calls to reduce code cache size.
 *
 * The OUTPUT_TEXT define controls the format of the trace: text or binary.
 * Creating a text trace file makes the tool an order of magnitude (!) slower
 * than creating a binary file; thus, the default is binary.
 */

#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"

#include "ice_snapshot.h"
#include "deliever_package.h"
#include "hashtable.h"
#include "range_manager.h"
#include "ntdll_simple.h"


// #define SOCKET
#define FILE

#define NEG_ONE 0xFFFFFFFF

static int buf;

extern module_data_t *appmod;
// file_t output_file = INVALID_FILE;

range_manager_t snapshot_manager;

static int save_process_running_env(void *drcontext);

void take_process_snapshot(void *drcontext , TEB* pteb, 
            unsigned int eflags, 
            unsigned int edi,
            unsigned int esi,
            unsigned int edx,
            unsigned int ecx,
            unsigned int ebx,
            unsigned int eax,
            unsigned int eip,
            unsigned int esp,
            unsigned int ebp);


// bool iter_func1(ptr_uint_t id, void * entry, void * iter_data);

typedef struct _cpu_snapshot_t
{
    unsigned int ebp;
    unsigned int esp;
    unsigned int eip;

    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    unsigned int esi;
    unsigned int edi;
    unsigned int eflags;

    unsigned int fs_base;

}cpu_snapshot_t;

cpu_snapshot_t cpu_snapshot = {0} ;


//////


static void clean_call(void);
static void instrument_basic_process_snapshot(void *drcontext, instrlist_t *ilist, instr_t *where);

dr_emit_flags_t
event_bb_insert_basic_snapshot(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
        static int i= 0;

    if (instr_get_app_pc(instr) == NULL || !instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    // if ((int)instr_get_app_pc(instr) < 0x500000)
        // dr_printf("0x%08x\n", instr_get_app_pc(instr));

    // if(instr_get_app_pc(instr) == appmod->start + 0x1017 || instr_get_app_pc(instr) == appmod->start + 0x1035 || instr_get_app_pc(instr) == 0x0041548C)
    // if(instr_get_app_pc(instr) == 0x0041548C)    //real sample branch point
    //if(instr_get_app_pc(instr) == 0x00401000)    //real sample branch point
    // if (instr_get_app_pc(instr) == appmod->start + 0x1017)
// #ifdef MEM_TRACE
    if (instr_get_app_pc(instr) == appmod->entry_point || instr_get_app_pc(instr) == appmod->start + 0x1017 || instr_get_app_pc(instr) == appmod->start + 0x1035)
    // if(instr_get_app_pc(instr) == appmod->entry_point || instr_get_app_pc(instr) == 0x0041548C)    //real sample branch point
// #else
    // if (instr_get_app_pc(instr) == appmod->entry_point)
//     if(instr_get_app_pc(instr) == 0x0041548C)    //real sample branch point
// #endif
    {
        instrument_basic_process_snapshot(drcontext, bb, instr);
    }
    return DR_EMIT_DEFAULT;
}

// static void
// process_snapshot(unsigned int eflags, 
//             unsigned int edi,
//             unsigned int esi,
//             unsigned int edx,
//             unsigned int ecx,
//             unsigned int ebx,
//             unsigned int eax,
//             unsigned int eip,
//             unsigned int esp,
//             unsigned int ebp)
static void
process_snapshot(unsigned int eflags, 
            unsigned int eip, 
            unsigned int edi,
            unsigned int esi,
            unsigned int ebp,
            unsigned int esp,
            unsigned int ebx,
            unsigned int edx,
            unsigned int ecx,
            unsigned int eax)
{
    TEB * pteb;
    PEB* ppeb;
    void *drcontext = dr_get_current_drcontext();

    unsigned char * ptmp;

    dr_log(NULL, LOG_ALL, 1, "jack:enter clean call\n");


    pteb = getTEB();

    take_process_snapshot(drcontext, pteb ,  eflags, 
            edi,
            esi,
            edx,
            ecx,
            ebx,
            eax,
            eip,
            // esp + 0x24,   //jack: adjust dr impact
            esp,
            ebp);
    dr_log(NULL, LOG_ALL, 1, "jack:exit clean call\n");
}

void
instrument_basic_process_snapshot(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    instr_t *instr, *call, *restore;
    opnd_t   opnd1, opnd2;
    // reg_id_t reg1, reg2;
    drvector_t allowed;
    //per_thread_t *data;
    app_pc pc;

    //data = drmgr_get_tls_field(drcontext, tls_index);

    /* Steal two scratch registers.
     * reg2 must be ECX or RCX for jecxz.
     */
    // drreg_init_and_fill_vector(&allowed, false);
    // drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // if (drreg_reserve_register(drcontext, ilist, where, &allowed, &reg2) !=
    //     DRREG_SUCCESS ||
    //     drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS) {
    //     DR_ASSERT(false); /* cannot recover */
    //     drvector_delete(&allowed);
    //     return;
    // }
    // drvector_delete(&allowed);
    // reg2 = reg_cx;
    // reg1 = reg_2;

    //added by jack
    instr = INSTR_CREATE_pusha(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);
    
    //push ebp
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_EBP, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push esp
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_ESP, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    //push pc
    pc = instr_get_app_pc(where);
    dr_printf("[ice_snapshot]: pc: %x\n", pc);
    opnd1 = OPND_CREATE_INT32(pc);
    instr = INSTR_CREATE_push_imm(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // //push eax
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_EAX, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push ebx
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_EBX, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push ecx
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_ECX, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push edx
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_EDX, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push esi
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_ESI, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // //push edi
    // drreg_get_app_value(drcontext, ilist, where, DR_REG_EDI, reg1);
    // opnd1 = opnd_create_reg(reg1);
    // instr = INSTR_CREATE_push(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // push eflags
    instr = INSTR_CREATE_pushf(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);

    //process_snapshot()
    instr = INSTR_CREATE_call(drcontext, opnd_create_pc(process_snapshot));
    instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_EAX);
    // instr = INSTR_CREATE_pop(drcontext, opnd1);
    // instrlist_meta_preinsert(ilist, where, instr);

    instr = INSTR_CREATE_popf(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // opnd1 = opnd_create_reg(DR_REG_ESP);
    // opnd2 = opnd_create_base_disp(DR_REG_ESP, DR_REG_NULL, 0, -4, OPSZ_lea);
    // instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    // instrlist_meta_preinsert(ilist, where, instr);

    //popa
    instr = INSTR_CREATE_popa(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);
}

/* instrument_instr is called whenever a memory reference is identified.
 * It inserts code before the memory reference to to fill the memory buffer
 * and jump to our own code cache to call the clean_call when the buffer is full.
 */
void
instrument_basic_process_snapshot2(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    instr_t *instr, *call, *restore;
    opnd_t   opnd1, opnd2;
    reg_id_t reg1, reg2;
    drvector_t allowed;
    app_pc pc;



    // data = drmgr_get_tls_field(drcontext, tls_index);

    // /* Steal two scratch registers.
    //  * reg2 must be ECX or RCX for jecxz.
    //  */
    // drreg_init_and_fill_vector(&allowed, false);
    // drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // if (drreg_reserve_register(drcontext, ilist, where, &allowed, &reg2) !=
    //     DRREG_SUCCESS ||
    //     drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS) {
    //     DR_ASSERT(false); /* cannot recover */
    //     drvector_delete(&allowed);
    //     return;
    // }
    // drvector_delete(&allowed);

    //added by jack
    reg1 = DR_REG_EBP;
    instr = INSTR_CREATE_pusha(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);

    
    //push ebp
    drreg_get_app_value(drcontext, ilist, where, DR_REG_EBP, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push esp
    drreg_get_app_value(drcontext, ilist, where, DR_REG_ESP, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push pc
    pc = instr_get_app_pc(where);
    dr_printf("[ice_snapshot]: pc: %x\n", pc);
    opnd1 = OPND_CREATE_INT32(pc);
    instr = INSTR_CREATE_push_imm(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push eax
    drreg_get_app_value(drcontext, ilist, where, DR_REG_EAX, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push ebx
    drreg_get_app_value(drcontext, ilist, where, DR_REG_EBX, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push ecx
    drreg_get_app_value(drcontext, ilist, where, DR_REG_ECX, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push edx
    drreg_get_app_value(drcontext, ilist, where, DR_REG_EDX, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push esi
    drreg_get_app_value(drcontext, ilist, where, DR_REG_ESI, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push edi
    drreg_get_app_value(drcontext, ilist, where, DR_REG_EDI, reg1);
    opnd1 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    //push eflags
    instr = INSTR_CREATE_pushf(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);

    //clean_call1()
    instr = INSTR_CREATE_call(drcontext, opnd_create_pc(process_snapshot));
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(DR_REG_EAX);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    
    //popa
    instr = INSTR_CREATE_popa(drcontext);
    instrlist_meta_preinsert(ilist, where, instr);

    return;
}

//added by jack
//To save process runing environment 
static int save_process_running_env(void *drcontext)
{
    // uint total_size = 0;

    // dr_module_iterator_t *iter = dr_module_iterator_start();


    // dr_log(NULL, LOG_ALL, 1, "jack: enter save_process_running_env\n" );

    // while (dr_module_iterator_hasnext(iter)) {
    //     module_data_t *data = dr_module_iterator_next(iter);
        
    //     dr_log(NULL, LOG_ALL, 1, "jack: module path: %s\n", data->full_path );

    //     dr_log(NULL, LOG_ALL, 1, "jack: %x --> %x : size: %x \n", data->start, data->end, data->end - data->start);

    //     total_size += (data->end - data->start);
        
    //     dr_free_module_data(data);
    // }

    // dr_log(NULL, LOG_ALL, 1, "jack: total module size: %x\n",  total_size);


    // dr_module_iterator_stop(iter);

    // dr_log(NULL, LOG_ALL, 1, "jack: exit save_process_running_env\n" );


    return 0;
	
}


typedef int (*func_envwalker_callback_t) (void * drcontext, void* pBuf, unsigned int len );

#define SAVE_UNIT 0x1000

#define HASH_BITS 13 

#define PAGE_ALIGN_MASK 0xfffff000


int recorder_save(void *drcontext, byte* pBuf, unsigned int len)
{
    byte *range_begin, *range_end;

    dr_printf("[ice_snapshot]: enter recorder_save: loc: %p , len: %x\n", pBuf, len);
    if (pBuf != NULL) {
        range_begin = (byte*)((int)pBuf & PAGE_ALIGN_MASK);
        range_end = (byte *)(((int)(pBuf + len - 1) & PAGE_ALIGN_MASK) + (~PAGE_ALIGN_MASK + 1));

        range_manager_add(&snapshot_manager, range_begin, range_end);
    }

    dr_printf("[ice_snapshot]: exit recorder_save\n");

    return 0;
}

void record_dump(byte *range_begin, byte *range_end)
{
    safe_send_memory_block(range_begin, range_end - range_begin, false);
}


int recorder_flush()
{
    dr_printf("[ice_snapshot]: enter recorder_flush\n");

    range_manager_dump(&snapshot_manager);

    dr_printf("[ice_snapshot]: exit recorder_flush\n");
    
    return 0;
}

int recorder_deinit()
{
    dr_printf("[ice_snapshot]: enter recorder_deinit\n");
    range_manager_delete(&snapshot_manager);
    dr_printf("[ice_snapshot]: exit recorder_deinit\n");
}


int walk_process_envionment(void *drcontext, PEB * ppeb , func_envwalker_callback_t cb)
{
    PEB_LDR_DATA *ldr = 0;
    LIST_ENTRY *e, *mark;
    LDR_MODULE *mod;
    int i;
    void** heapPointerArray;

    dr_printf("[ice_snapshot]: enter walk_process_envionment\n");

    cb( drcontext,ppeb, SAVE_UNIT);

    //handle LoaderData

    ldr = ppeb->LoaderData;


    cb( drcontext, ldr, SAVE_UNIT);


    mark = &ldr->InMemoryOrderModuleList;

    
    for (e = mark->Flink; e != mark; e = e->Flink) {

        mod = (LDR_MODULE *) ((char *)e - offsetof(LDR_MODULE, InMemoryOrderModuleList));

        cb(drcontext, mod, SAVE_UNIT);

        cb(drcontext, mod->FullDllName.Buffer, SAVE_UNIT);

        cb(drcontext, mod->BaseDllName.Buffer, SAVE_UNIT);


        dr_printf("[ice_snapshot]: module: %p , %x\n", mod->BaseAddress, mod->SizeOfImage );

        cb(drcontext, mod->BaseAddress, mod->SizeOfImage);
    }


    //handle ProcessParameters
    cb(drcontext, ppeb->ProcessParameters, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->CurrentDirectoryPath.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->DllPath.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->ImagePathName.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->CommandLine.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->Environment, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->DesktopName.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->ShellInfo.Buffer, SAVE_UNIT);
    cb(drcontext, ppeb->ProcessParameters->RuntimeData.Buffer, SAVE_UNIT);


    dr_printf("[ice_snapshot]: jack: handle ProcessHeaps\n");
    dr_printf("[ice_snapshot]: ProcessHeap : 0x%08x\n", ppeb->ProcessHeap);

    //handle ProcessHeaps
    heapPointerArray = ppeb->ProcessHeaps;
    cb(drcontext, heapPointerArray, SAVE_UNIT);
    for(i = 0; i < ppeb-> NumberOfHeaps;i++)
    {
        dr_printf("[ice_snapshot]: save heap at 0x%08x\n", heapPointerArray[i]);
        cb( drcontext,heapPointerArray[i] , 0x100*SAVE_UNIT);
    }
   
    //ActivationContextData     //for GetModuleHandle fail
    cb(drcontext, ppeb->ActivationContextData,  0x8*SAVE_UNIT);

    //SystemDefaultActivationContextData    //for GetModuleHandle fail
    cb(drcontext, ppeb->SystemDefaultActivationContextData,  0x8*SAVE_UNIT);

    //AnsiCodePageData
    cb(drcontext, ppeb->AnsiCodePageData, SAVE_UNIT);

    //OemCodePageData
    cb(drcontext, ppeb->OemCodePageData, SAVE_UNIT);

    //UnicodeCaseTableData
    cb(drcontext, ppeb->UnicodeCaseTableData, SAVE_UNIT);

    //pUnused :  jack: this is for ntdll!SbAtomicCaptureContextGuid doesn't dead loop in emu
    cb(drcontext, ppeb->pUnused, SAVE_UNIT);

    dr_printf("[ice_snapshot]: exit walk_process_envionment\n");
}


int walk_thread_envionment( void *drcontext, TEB * pteb , func_envwalker_callback_t cb )
{
    PEXCEPTION_REGISTRATION pExceptionList;
    void* pStackBase;
    void* pStackLimit;

    dr_printf("[ice_snapshot]: enter walk_thread_envionment\n");

    dr_printf("[ice_snapshot]: teb.StackBase:%p teb.StackLimit:%p\n", pteb->StackBase, pteb->StackLimit);


    cb(drcontext, pteb, SAVE_UNIT);

    pExceptionList = pteb->ExceptionList;


    for(  ; pExceptionList !=  NEG_ONE && pExceptionList !=  NULL;  pExceptionList = pExceptionList->prev)
    {
        cb(drcontext, pExceptionList , SAVE_UNIT);
        
    }

    pStackBase = pteb->StackBase;
    pStackLimit = pteb->StackLimit;

    cb(drcontext, pStackLimit,  (unsigned int)pteb->StackBase - (unsigned int)pteb->StackLimit);

    //pteb->ActivationContextStackPointer
    cb(drcontext, pteb->ActivationContextStackPointer, SAVE_UNIT);

    walk_process_envionment(drcontext, pteb->ProcessEnvironmentBlock,  cb);

    cb(drcontext, KUSER_SHARED_DATA_ADDRESS, 0x20 * SAVE_UNIT);


    dr_printf("[ice_snapshot]: exit walk_thread_envionment\n");

    return 0;
}

void stack_snapshot(void *drcontext, TEB *pteb)
{
    send_snapshot((byte*)pteb->StackLimit, (byte*)pteb->StackBase - (byte *)pteb->StackLimit);
}



int cpu_state_snapshot(void *drcontext, void* pteb, 
            unsigned int eflags, 
            unsigned int edi,
            unsigned int esi,
            unsigned int edx,
            unsigned int ecx,
            unsigned int ebx,
            unsigned int eax,
            unsigned int eip,
            unsigned int esp,
            unsigned int ebp)
{
    unsigned char* pb = 0;
    int i;

    dr_printf("[ice_snapshot]: enter cpu_state_snapshot\n");

    cpu_snapshot.ebp =  ebp;

    cpu_snapshot.esp =  esp;//reg_get_value(DR_REG_ESP, &mcontext);

    cpu_snapshot.eip =  eip;

    cpu_snapshot.eax =  eax;

    cpu_snapshot.ebx =  ebx;

    cpu_snapshot.ecx =  ecx;//reg_get_value(DR_REG_ECX, &mcontext);;

    cpu_snapshot.edx =  edx;

    cpu_snapshot.esi =  esi;

    cpu_snapshot.edi =  edi;

    cpu_snapshot.eflags =  eflags;

    cpu_snapshot.fs_base = (unsigned int)pteb;

    dr_printf("[ice_snapshot]: cpu_snapshot: ebp: %x  esp: %x eip: %x\n", cpu_snapshot.ebp,
                            cpu_snapshot.esp,
                            cpu_snapshot.eip);
    dr_printf("[ice_snapshot]: cpu_snapshot: eax: %x ebx: %x ecx: %x edx: %x\n", cpu_snapshot.eax,
                            cpu_snapshot.ebx,
                            cpu_snapshot.ecx,
                            cpu_snapshot.edx);
    dr_printf("[ice_snapshot]: cpu_snapshot: eax: %x ebx: %x ecx: %x edx: %x\n", cpu_snapshot.eax,
                            cpu_snapshot.ebx,
                            cpu_snapshot.ecx,
                            cpu_snapshot.edx);
    dr_printf("[ice_snapshot]: cpu_snapshot: esi: %x  edi: %x eflags: %x fs_base: %x \n", 
                            cpu_snapshot.esi,
                            cpu_snapshot.edi,
                            cpu_snapshot.eflags,
                            cpu_snapshot.fs_base );

    pb = (unsigned char*) cpu_snapshot.esp;

    for( i = 0; i<0x40 ; i++)
    {
        if(i % 0x10 == 0)
        {
            dr_printf("\n");
        }
        
        dr_printf("%2x ", *pb);
        pb +=1;
    }

    dr_printf("\n");


    send_cpu_snapshot(&cpu_snapshot, sizeof(cpu_snapshot));

    dr_printf("[ice_snapshot]: exit cpu_state_snapshot\n");

    return 0;

}


int patch_back_dr_hook(void *drcontext)
{
    before_hook_t *before_hook;
    int before_hook_count;

    before_hook = get_code_before_hook_buffer();
    before_hook_count = get_code_before_hook_count();

    if (before_hook_count == 0)
    {
        dr_printf("[ice_snapshot]: get_code_before_hook_count return 0 \n");
        return -1;
    } 


    while (before_hook_count > 0) {
        send_memory_trace(before_hook->target_addr, before_hook->buffer, MAX_HOOK_SIZE);

        before_hook++;
        before_hook_count--;
    }
    return 0;
}

extern range_manager_t manager;

void take_process_snapshot(void *drcontext , TEB* pteb, 
            unsigned int eflags, 
            unsigned int edi,
            unsigned int esi,
            unsigned int edx,
            unsigned int ecx,
            unsigned int ebx,
            unsigned int eax,
            unsigned int eip,
            unsigned int esp,
            unsigned int ebp)
{
    static int s_i = 0;

    dr_printf("[ice_snapshot]: enter take_process_snapshot\n");

    // if (eip == 0x41548c) {
    //     if(s_i == 0)
    //         s_i=1;
    //     else
    //         return;
    // }

#ifdef MEM_TRACE
    if (eip == appmod->start + 0x1017 || eip == appmod->start + 0x1035) {
        dr_printf("[ice_snapshot]: hit : 0x%08x\n", eip);
        mem_trace_merge(dr_get_current_drcontext());
        range_manager_dump(&manager);

        cpu_state_snapshot(drcontext, pteb, eflags, 
            edi,
            esi,
            edx,
            ecx,
            ebx,
            eax,
            eip,
            esp,
            ebp);

        stack_snapshot(drcontext, pteb);

        if (eip == appmod->start + 0x1017)
            send_fork(appmod->start + 0x1019);
        if (eip == appmod->start + 0x1035)
            send_fork(appmod->start + 0x1037);
        // send_fork(0x41548e);
        // eip = 0x415493;
        goto done;
    }
#endif

    cpu_state_snapshot(drcontext, pteb, eflags, 
            edi,
            esi,
            edx,
            ecx,
            ebx,
            eax,
            eip,
            esp,
            ebp);


    // recorder_init();
    range_manager_init(&snapshot_manager);
    range_manager_set_free_callback(&snapshot_manager, record_dump);

    walk_thread_envionment(drcontext,  pteb , recorder_save);

    recorder_flush();

    recorder_deinit();

    patch_back_dr_hook(drcontext);

#ifndef MEM_TRACE
    if (eip == appmod->start + 0x1017)
        send_fork(appmod->start + 0x1019);
    if (eip == appmod->start + 0x1035)
        send_fork(appmod->start + 0x1037);
    if (eip == 0x0041548C) {
        send_fork(0x41548e);
        eip = 0x415493;
    }
#endif

// // #ifndef MEM_TRACE // IF NOT DEF
// //     if (eip == appmod->start + 0x1000)
// //         send_fork(appmod->start + 0x1000);
// // #endif

done:
    dr_printf("[ice_snapshot]: exit take_process_snapshot\n");
}

