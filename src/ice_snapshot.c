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
#include "dr_ir_opnd.h"
#include "range_manager.h"
#include "deliever_package.h"


/* Each ins_ref_t describes an executed instruction. */
typedef struct _mem_trace_t {
    app_pc pc;
    byte *target_addr;
    int unit_size;

    // used by rep prefix
    int unit_num;
} mem_trace_t;

range_manager_t manager;

/* Max number of ins_ref a buffer can have */
#define MAX_NUM_TRACE_REFS 8192

/* The size of the memory buffer for holding ins_refs. When it fills up,
 * we dump data from the buffer to the file.
 */
#define MEM_BUF_SIZE (sizeof(mem_trace_t) * MAX_NUM_TRACE_REFS)

/* Thread-private data */
typedef struct {
    int thread_index;

    char   *buf_ptr;
    char   *buf_base;
    /* buf_end holds the negative value of real address of buffer end. */
    ptr_int_t buf_end;

    bool last_instr_has_rep;

    int fs_selector;
    int fs_base;
} per_thread_t;

file_t output_file;
static size_t page_size;
static client_id_t client_id;
static app_pc code_cache;
static void  *mutex;    /* for multithread support */
module_data_t *appmod = NULL;

static int tls_index;

static int thread_count;
static void *thread_count_lock;

static void __send_memory_trace(byte *trace_begin, byte *trace_end);

static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);

static dr_emit_flags_t event_bb_insert_memory_trace(void *drcontext, void *tag, instrlist_t *bb,
                                       instr_t *instr, bool for_trace, bool translating,
                                       void *user_data);
extern dr_emit_flags_t event_bb_insert_basic_snapshot(void *drcontext, void *tag, instrlist_t *bb,
                                       instr_t *instr, bool for_trace, bool translating,
                                       void *user_data);

static void clean_call(void);
void mem_trace_merge(void *drcontext);
static void code_cache_init(void);
static void code_cache_exit(void);

static void instrument_normal_instr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_cx, reg_id_t reg_2);
static void instrument_rep_instr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_cx, reg_id_t reg_2);
static void instrument_rep_instr_next(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_cx, reg_id_t reg_2);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = {sizeof(ops), 3, false};

    /* Specify priority relative to other instrumentation operations: */
    drmgr_priority_t instru_mem_trace_priority = {
        sizeof(instru_mem_trace_priority), /* size of struct */
        "instru_memory_trace",       /* name of our operation */
        NULL,             /* optional name of operation we should precede */
        NULL,             /* optional name of operation we should follow */
        1};               /* numeric priority */

    drmgr_priority_t instru_basic_snapshot_priority = {
        sizeof(instru_basic_snapshot_priority),
        "instru_basic_snapshot",
        // "instru_memory_trace",
        NULL,
        NULL, 
        0};

    int i;

    dr_set_client_name("Ice_snapshot", "NULL");

    page_size = dr_page_size();
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT(false);
    client_id = id;

    appmod = dr_get_main_module();

    dr_register_exit_event(event_exit);
    ASSERT(drmgr_register_thread_init_event(event_thread_init), "");
    ASSERT(drmgr_register_thread_exit_event(event_thread_exit), "");

#ifdef MEM_TRACE
    ASSERT(drmgr_register_bb_instrumentation_event(NULL /*analysis func*/,
                                                 event_bb_insert_memory_trace,
                                                 &instru_mem_trace_priority), "");
#endif
    ASSERT(drmgr_register_bb_instrumentation_event(NULL /*analysis func*/,
                                                 event_bb_insert_basic_snapshot,
                                                 &instru_basic_snapshot_priority), "");

    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    thread_count = 0;
    thread_count_lock = dr_mutex_create();

    range_manager_init(&manager);
    range_manager_set_free_callback(&manager, __send_memory_trace);

#ifdef FILE 
    output_file = dr_open_file(".\\output", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

    if (output_file == INVALID_FILE) {
        dr_printf("[ice_snapshot]: Open log file error\n");
        return 0;
    }
#endif

    dr_enable_console_printing();
    dr_printf("[ice_snapshot]: Ice_snapshot running...\n");

    code_cache_init();
}

extern file_t output_file;
static void
event_exit()
{
    code_cache_exit();

    range_manager_delete(&manager);

#ifdef FILE
    if (output_file != INVALID_FILE)
        dr_close_file(output_file);
#endif

    dr_mutex_destroy(thread_count_lock);

    ASSERT(drmgr_unregister_tls_field(tls_index), "");
    ASSERT(drmgr_unregister_thread_init_event(event_thread_init), "");
    ASSERT(drmgr_unregister_thread_exit_event(event_thread_exit), "");
    ASSERT(drmgr_unregister_bb_insertion_event(event_bb_insert_basic_snapshot), "");
#ifdef MEM_TRACE
    ASSERT(drmgr_unregister_bb_insertion_event(event_bb_insert_memory_trace), "");
#endif

    dr_free_module_data(appmod);

    ASSERT(drreg_exit() == DRREG_SUCCESS, "");
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data;
    int fs_selector, fs_base;

    /* allocate thread private data */
    data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, data);
    data->buf_base = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    data->buf_ptr  = data->buf_base;
    /* set buf_end to be negative of address of buffer end for the lea later */
    data->buf_end  = -(ptr_int_t)(data->buf_base + MEM_BUF_SIZE);

    data->last_instr_has_rep = false;

    __asm mov ax, fs;
    __asm cwde;
    __asm mov fs_selector, eax;
    data->fs_selector = fs_selector;

    __asm mov eax, fs : [0x18]
    __asm mov fs_base, eax;
    data->fs_base = fs_base;

    dr_printf("[ice_snapshot]: thread selector : 0x%08x\n", data->fs_selector);
    dr_printf("[ice_snapshot]: thread base : 0x%08x\n", data->fs_base);

    dr_mutex_lock(thread_count_lock);
    data->thread_index = thread_count;
    thread_count++;
    dr_mutex_unlock(thread_count_lock);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;

    data = drmgr_get_tls_field(drcontext, tls_index);

    if (data->thread_index == 0){
        // mem_trace_merge(drcontext);

        // dr_printf("total : %d trace\n", manager.size);

        // dr_printf("max ptr : 0x%08x\n", ptr);

        //log_file = dr_open_file("D:\\output\\mem_trace", DR_FILE_WRITE_OVERWRITE);
        // range_manager_dump(&manager);

        //dr_close_file(log_file);
    }

    dr_thread_free(drcontext, data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

bool snapshot_begin = false;

bool need_to_instrument(void *drcontext, void *tag, instrlist_t *instrlist,
                instr_t *instr)
{
    per_thread_t *data;

    if (instr_get_app_pc(instr) == NULL || !instr_is_app(instr))
        return false;

    if (snapshot_begin == false)
        return false;

    //if (instr_get_app_pc(instr) == appmod->entry_point)
    //    return true;

    data = drmgr_get_tls_field(drcontext, tls_index);
    if (data->thread_index != 0)
        return false;

    if (data->last_instr_has_rep == true)
        return true;

    if (instr_writes_memory(instr) == false)
        return false;

    if (instr_get_opcode(instr) == OP_push || 
        instr_get_opcode(instr) == OP_push_imm || 
        instr_get_opcode(instr) == OP_pusha ||
        instr_get_opcode(instr) == OP_pushf)
        return false;

    if (instr_get_opcode(instr) == OP_call || 
        instr_get_opcode(instr) == OP_call_ind || 
        instr_get_opcode(instr) == OP_call_far || 
        instr_get_opcode(instr) == OP_call_far_ind)
        return false;

    return true;
}





static void
__send_memory_trace(byte *trace_begin, byte *trace_end)
{
    // dr_printf("0x%08x : 0x%08x, ", trace_begin, trace_end);
    // send_memory_trace(trace_begin, trace_begin, trace_end - trace_begin);
    safe_send_memory_block(trace_begin, trace_end - trace_begin, true);
}

void
mem_trace_merge(void *drcontext)
{
    per_thread_t *data;
    int num_refs;
    mem_trace_t *mem_trace;
    int i = 0;

    data = drmgr_get_tls_field(drcontext, tls_index);
    mem_trace = (mem_trace_t *)data->buf_base;

    ASSERT(data->thread_index == 0, "[ice_snapshot]: Only trace main thread");

    while (mem_trace < data->buf_ptr) {
        byte *range_begin, *range_end;

        range_begin = mem_trace->target_addr;
        range_end = range_begin + mem_trace->unit_num * mem_trace->unit_size;

        range_manager_add(&manager, range_begin, range_end);
        mem_trace++;
    }

    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->buf_ptr   = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    mem_trace_merge(drcontext);
}

static void
code_cache_init(void)
{
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext  = dr_get_current_drcontext();
    code_cache = dr_nonheap_alloc(page_size,
                                  DR_MEMPROT_READ  |
                                  DR_MEMPROT_WRITE |
                                  DR_MEMPROT_EXEC);
    ilist = instrlist_create(drcontext);
    /* The lean procecure simply performs a clean call, and then jumps back. */
    /* Jump back to DR's code cache. */
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    /* Clean call */
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);
    /* Encode the instructions into memory and clean up. */
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    DR_ASSERT((size_t)(end - code_cache) < page_size);
    instrlist_clear_and_destroy(drcontext, ilist);
    /* Set the memory as just +rx now. */
    dr_memory_protect(code_cache, page_size, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}


static void
code_cache_exit(void)
{
    dr_nonheap_free(code_cache, page_size);
}


////////////////////////////////////////////////////////////////////////////
//////       instrument
#include "instrument_helper.h"

/* event_bb_insert calls instrument_instr to instrument every
 * application memory reference.
 */
static dr_emit_flags_t
event_bb_insert_memory_trace(void *drcontext, void *tag, instrlist_t *instrlist,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
    per_thread_t *data;
    char *pc;
    reg_id_t reg_cx, reg_2;
    drvector_t allowed;
    instr_t *restore;

    if (instr_get_app_pc(instr) == appmod->entry_point)
        snapshot_begin = true;

    if (need_to_instrument(drcontext, tag, instrlist, instr) == false) {
        return DR_EMIT_DEFAULT;
    }

    data = drmgr_get_tls_field(drcontext, tls_index);

    // reserve rcx for jecxz
    // drreg_init_and_fill_vector(&allowed, false);
    // drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // if (drreg_reserve_register(drcontext, instrlist, instr, &allowed, &reg_cx) !=DRREG_SUCCESS ||
    //     drreg_reserve_register(drcontext, instrlist, instr, NULL, &reg_2) != DRREG_SUCCESS) {
    //     DR_ASSERT(false); /* cannot recover */
    //     drvector_delete(&allowed);
    //     return;
    // }
    // drvector_delete(&allowed);
    reg_cx = DR_REG_XCX;
    reg_2 = DR_REG_XDX;

    instrument_save_reg_on_stack(drcontext, instrlist, instr, reg_cx, 4);
    instrument_save_reg_on_stack(drcontext, instrlist, instr, reg_2, 8);
    // drreg 有的时候不太靠谱 所以通过把值保存在栈上自行reserve寄存器

    if (data->last_instr_has_rep == true) {
        instrument_rep_instr_next(drcontext, instrlist, instr, reg_cx, reg_2);
    }

    pc = instr_get_app_pc(instr);
    if (*pc == '\xF2' || *pc == '\xF3')
        data->last_instr_has_rep = true;
    else
        data->last_instr_has_rep = false;

    if (instr_writes_memory(instr) == true) {
        pc = instr_get_app_pc(instr);
        if (*pc == '\xF2' || *pc == '\xF3') {
            // 对于有rep, repz或repnz前缀的指令, 没办法直接拿到这条指令修改的内存的
            // 长度, 目前的解决方案是看指令前后cx寄存器的差值.
            // 由于 bb_insert 只允许将指令添加到当前build的指令前, 因此需要添加指令
            // 到rep指令的下一条指令之前去获取rep指令执行完之后的cx寄存器的值, 因此需
            // 要两次instrument_instr
            instrument_rep_instr(drcontext, instrlist, instr, reg_cx, reg_2);
        } else {
            instrument_normal_instr(drcontext, instrlist, instr, reg_cx, reg_2);
        }
    }

    // if (drreg_unreserve_register(drcontext, instrlist, instr, reg_cx) != DRREG_SUCCESS ||
    //     drreg_unreserve_register(drcontext, instrlist, instr, reg_2) != DRREG_SUCCESS)
    //     DR_ASSERT(false);
    instrument_get_reg_from_stack(drcontext, instrlist, instr, reg_cx, 4);
    instrument_get_reg_from_stack(drcontext, instrlist, instr, reg_2, 8);
    
    return DR_EMIT_DEFAULT;
}

/* instrument_instr is called whenever a memory reference is identified.
 * It inserts code before the memory reference to to fill the memory buffer
 * and jump to our own code cache to call the clean_call when the buffer is full.
 */
static void
instrument_normal_instr(void *drcontext, 
                        instrlist_t *ilist, instr_t *where, 
                        reg_id_t reg_cx, reg_id_t reg_2)
{
    instr_t *instr, *restore;
    opnd_t opnd1, opnd2, mem_ref_opnd;
    int mem_ref_opnd_size;

    memory_reference_opnd_test(where);

    // return point
    restore = INSTR_CREATE_label(drcontext);
    
    instrument_main_thread_test(drcontext, ilist, where, reg_cx, reg_2, restore);

    /* The following assembly performs the following instructions
     * buf_ptr->target_addr = target_addr;
     * buf_ptr->unit_size = length;
     * buf_ptr->unit_size = 1;
     * buf_ptr++;
     * if (buf_ptr == buf_end_ptr)
     *    clean_call();
     */
    // reg_2 already has per_thread_data
    // Load data->buf_ptr into reg_cx
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    mem_ref_opnd = memory_reference_opnd(where);
    base_disp_opnd_test(mem_ref_opnd);
    mem_ref_opnd_size = opnd_size_in_bytes(opnd_get_size(mem_ref_opnd));

    instrument_load_dst_address(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);

    // opnd_size has been changed
    opnd1 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, unit_size));
    opnd2 = OPND_CREATE_INT32(mem_ref_opnd_size);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    //set unit_num to 1 for normal instructions
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = OPND_CREATE_INT32(1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, unit_num));
    opnd2 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    instrument_update_buf_ptr(drcontext, ilist, where, reg_cx, reg_2);
    // jump to code_cache
    instrument_out_of_buf_test(drcontext, ilist, where, reg_cx, reg_2);

    /* Restore scratch registers */
    instrlist_meta_preinsert(ilist, where, restore);
}

static void 
instrument_rep_instr(void *drcontext, 
                     instrlist_t *ilist, instr_t *where, 
                     reg_id_t reg_cx, reg_id_t reg_2)
{
    instr_t *instr, *call, *restore;
    opnd_t opnd1, opnd2, mem_ref_opnd;
    int i, mem_ref_opnd_size;

    memory_reference_opnd_test(where);

    // return point
    restore = INSTR_CREATE_label(drcontext);

    instrument_main_thread_test(drcontext, ilist, where, reg_cx, reg_2, restore);

    // reg_2 has per_thread_data
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    mem_ref_opnd = memory_reference_opnd(where);
    base_disp_opnd_test(mem_ref_opnd);
    mem_ref_opnd_size = opnd_size_in_bytes(opnd_get_size(mem_ref_opnd));

    instrument_load_dst_address(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);

    opnd1 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, unit_size));
    opnd2 = OPND_CREATE_INT32(mem_ref_opnd_size);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // save cx
    // 这段代码有个奇怪的bug, 把mem_trace 放 reg_cx 里, 把app_reg_cx放 reg_2
    // 里程序会卡住, 调换一下把mem_trace 放 reg_2 里就正常
    // 所以多加一条 mov reg_2, reg_cx
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = opnd_create_reg(reg_cx);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // drreg_get_app_value(drcontext, ilist, where, DR_REG_XCX, reg_cx);
    instrument_get_reg_from_stack(drcontext, ilist, where, reg_cx, 4);

    opnd1 = OPND_CREATE_MEMPTR(reg_2, offsetof(mem_trace_t, unit_num));
    opnd2 = opnd_create_reg(reg_cx);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // return point
    instrlist_meta_preinsert(ilist, where, restore);
}


static void 
instrument_rep_instr_next(void *drcontext, 
                          instrlist_t *ilist, instr_t *where, 
                          reg_id_t reg_cx, reg_id_t reg_2)
{
    instr_t *instr, *call, *restore, *instrument;
    opnd_t opnd1, opnd2;

    // return point
    restore = INSTR_CREATE_label(drcontext);

    opnd1 = opnd_create_reg(DR_REG_XCX);
    instr = INSTR_CREATE_push(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    instrument_main_thread_test(drcontext, ilist, where, reg_cx, reg_2, restore);

    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_cx = old_cx
    // neg reg_cx
    // reg_cx += new_cx
    // neg reg_cx
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, unit_num));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_neg(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // get true cx
    //drreg_get_app_value(drcontext, ilist, where, DR_REG_XCX, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    instr = INSTR_CREATE_pop(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg_2);
    opnd2 = opnd_create_base_disp(reg_2, reg_cx, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_neg(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, unit_num));
    opnd2 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    instrument_update_buf_ptr(drcontext, ilist, where, reg_cx, reg_2);
    // jump to code_cache
    instrument_out_of_buf_test(drcontext, ilist, where, reg_cx, reg_2);

    // return point
    instrlist_meta_preinsert(ilist, where, restore);
}
