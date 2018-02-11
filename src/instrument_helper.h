#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"

#include "dr_ir_opnd.h"

// 把寄存器的值保存在栈上或是从栈上取值
// 用来代替原本的 drreg_get_app_value() 因为这个API不知道为什么有的时候会出错
// 为了保证在不管在哪里 栈上的偏移都不变 因此不使用push和pop 而直接把值存到栈上 通过偏移来管理
// 为了不污染原本的栈 offset 必须为正数 由调用方自行管理
static void inline instrument_save_reg_on_stack(void *drcontext, 
                                        instrlist_t *ilist, instr_t *where,
                                        reg_id_t target_reg, int offset)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    opnd1 = opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, -offset, OPSZ_4);
    opnd2 = opnd_create_reg(target_reg);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}
static void inline instrument_get_reg_from_stack(void *drcontext,
                                        instrlist_t *ilist, instr_t *where,
                                        reg_id_t target_reg, int offset)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    opnd1 = opnd_create_reg(target_reg);
    opnd2 = opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, -offset, OPSZ_4);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}

// IN : reg_cx : empty, reg_2 : empty
// OUT : reg_cx : empty, reg_2 : per_thread_data
static void inline instrument_main_thread_test(void *drcontext,
                                        instrlist_t *ilist, instr_t *where,
                                        reg_id_t reg_cx, reg_id_t reg_2,
                                        instr_t *restore)
{
    opnd_t opnd1, opnd2;
    instr_t *instr, *instrument;

    instrument = INSTR_CREATE_label(drcontext);

    /* if data->thread_index == 0
     *     jmp instrument_instr
     * else
     *     jmp restore
     */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_2);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, thread_index));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_instr(instrument);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    instrlist_meta_preinsert(ilist, where, instrument);
}

// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : segment_base, reg_2 : empty
// 因为windows不支持自定义段, 因此除了 fs 指向的teb所在段之外, 其他段的基址都是0
// fs 里的选择子和 fs 段基址, 即teb地址在线程初始化的时候保存在per_thread_t里了
// 这段代码把segment_reg里的值和fs_selector做比较, 相等的话把reg_cx设为fs_base
// 否则把reg_cx设为0
static inline void instrument_segment_selector(void *drcontext, 
                                 instrlist_t *ilist, instr_t *where, 
                                 reg_id_t reg_cx, reg_id_t reg_2, reg_id_t segment_reg)
{
    opnd_t opnd1, opnd2;
    instr_t *instr, *fs_selector, *restore;

    fs_selector = INSTR_CREATE_label(drcontext);
    restore = INSTR_CREATE_label(drcontext);

    // reg_cx = fs_selector
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, fs_selector));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_2 = segment_reg
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = OPND_CREATE_INT32(0);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    opnd1 = opnd_create_reg(reg_32_to_16(reg_2));
    opnd2 = opnd_create_reg(segment_reg);
    instr = INSTR_CREATE_mov_seg(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_2 = -reg_2
    opnd1 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_neg(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_cx = reg_2 + reg_cx
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = opnd_create_base_disp(reg_cx, reg_2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // if reg_cx == 0
    //     jmp fs_selector
    opnd1 = opnd_create_instr(fs_selector);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // normal selector
    // reg_cx = 0
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_INT32(0);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // jmp restore
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // fs_selector:
    instrlist_meta_preinsert(ilist, where, fs_selector);

    // reg_cx = data->fs_base
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, fs_base));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // restore :
    // return point
    instrlist_meta_preinsert(ilist, where, restore);
}

// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : data->buf_ptr, reg_2 : dst_addr
static void inline instrument_load_dst_addr_has_seg(void *drcontext, 
                                    instrlist_t *ilist, instr_t *where,
                                    reg_id_t reg_cx, reg_id_t reg_2,
                                    opnd_t mem_ref_opnd)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    instrument_segment_selector(drcontext, ilist, where, reg_cx, reg_2, opnd_get_segment(mem_ref_opnd));
    // reg_cx = segment_base

    opnd1 = opnd_create_reg(reg_2);
    // need to set opnd_size to OPSZ_lea
    opnd_set_size(&mem_ref_opnd, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, mem_ref_opnd);
    instrlist_meta_preinsert(ilist, where, instr);

    // dst = dst + segment_base
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = opnd_create_base_disp(reg_cx, reg_2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_cx has been overwrite, load mem_trace again
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : empty, reg_2 : dst
// 如果 mem_ref_opnd 正好引用了reg_cx或者reg_2, 那么不能直接使用lea
static void inline instrument_compute_reg_conflict_dst(void *drcontext, 
                                    instrlist_t *ilist, instr_t *where,
                                    reg_id_t reg_cx, reg_id_t reg_2,
                                    opnd_t mem_ref_opnd)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    // 把寄存器的值恢复为当前app的真实值
    instrument_get_reg_from_stack(drcontext, ilist, where, reg_cx, 4);
    instrument_get_reg_from_stack(drcontext, ilist, where, reg_2, 8);

    opnd_set_size(&mem_ref_opnd, OPSZ_lea);

    opnd1 = opnd_create_reg(reg_2);
    // opnd2 = opnd_create_base_disp(reg_cx, reg_2, opnd_get_scale(mem_ref_opnd), opnd_get_disp(mem_ref_opnd), OPSZ_lea);
    // instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instr = INSTR_CREATE_lea(drcontext, opnd1, mem_ref_opnd);
    instrlist_meta_preinsert(ilist, where, instr);
}


// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : data->buf_ptr, reg_2 : dst_addr
static void inline instrument_load_dst_addr_reg_conflict(void *drcontext,
                                    instrlist_t *ilist, instr_t *where,
                                    reg_id_t reg_cx, reg_id_t reg_2,
                                    opnd_t mem_ref_opnd)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    instrument_compute_reg_conflict_dst(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);
    // reg_2 = dst

    // reg_cx has been overwrite, load mem_trace again
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : data->buf_ptr, reg_2 : dst_addr
static void inline instrument_load_dst_addr_has_seg_and_reg_conflict(void *drcontext,
                                    instrlist_t *ilist, instr_t *where,
                                    reg_id_t reg_cx, reg_id_t reg_2,
                                    opnd_t mem_ref_opnd)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    instrument_segment_selector(drcontext, ilist, where, reg_cx, reg_2, opnd_get_segment(mem_ref_opnd));
    // reg_cx = segment_base

    // save reg_cx on stack
    instrument_save_reg_on_stack(drcontext, ilist, where, reg_cx, 12);

    instrument_compute_reg_conflict_dst(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);
    // reg_2 = dst
    
    // get segment_base from stack
    instrument_get_reg_from_stack(drcontext, ilist, where, reg_cx, 12);

    // reg_2 = reg_cx + reg_2
    // dst = segment_base + dst
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = opnd_create_base_disp(reg_cx, reg_2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // reg_cx has been overwrite, load mem_trace again
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_cx);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = OPND_CREATE_MEMPTR(reg_cx, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


// IN : reg_cx : data->buf_ptr, reg_2 : empty
// OUT : reg_cx : data->buf_ptr, reg_2 : empty
static void inline instrument_load_dst_address(void *drcontext,
                                    instrlist_t *ilist, instr_t *where,
                                    reg_id_t reg_cx, reg_id_t reg_2,
                                    opnd_t mem_ref_opnd)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;
    bool reg_conflict, has_seg;

    if (opnd_get_segment(mem_ref_opnd) != DR_REG_NULL)
        has_seg = true;
    else
        has_seg = false;

    if (opnd_get_base(mem_ref_opnd) == reg_cx ||
        opnd_get_base(mem_ref_opnd) == reg_2 ||
        opnd_get_index(mem_ref_opnd) == reg_cx ||
        opnd_get_index(mem_ref_opnd) == reg_2)
        reg_conflict = true;
    else
        reg_conflict = false;

    if (has_seg == true && reg_conflict == true)
        instrument_load_dst_addr_has_seg_and_reg_conflict(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);
    else if (has_seg == true && reg_conflict == false)
        instrument_load_dst_addr_has_seg(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);
    else if (has_seg == false && reg_conflict == true)
        instrument_load_dst_addr_reg_conflict(drcontext, ilist, where, reg_cx, reg_2, mem_ref_opnd);
    else {
        // get the address by lea        
        opnd1 = opnd_create_reg(reg_2);
        // need to set opnd_size to OPSZ_lea
        opnd_set_size(&mem_ref_opnd, OPSZ_lea);
        instr = INSTR_CREATE_lea(drcontext, opnd1, mem_ref_opnd);
        instrlist_meta_preinsert(ilist, where, instr);
    }

    opnd1 = OPND_CREATE_MEMPTR(reg_cx, offsetof(mem_trace_t, target_addr));
    opnd2 = opnd_create_reg(reg_2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


// IN : reg_cx : buf_ptr, reg_2 : per_thread_data
// OUT : reg_cx : new_buf_ptr, reg_2, per_thread_data
static void inline instrument_update_buf_ptr(void *drcontext,
                                instrlist_t *ilist, instr_t *where,
                                reg_id_t reg_cx, reg_id_t reg_2)
{
    opnd_t opnd1, opnd2;
    instr_t *instr;

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = opnd_create_base_disp(reg_cx, DR_REG_NULL, 0, sizeof(mem_trace_t), OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_2);
    opnd1 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg_cx);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}

// IN : reg_cx : buf_ptr, reg_2 : per_thread_data
// OUT : instrument_end
static void inline instrument_out_of_buf_test(void *drcontext,
                                instrlist_t *ilist, instr_t *where,
                                reg_id_t reg_cx, reg_id_t reg_2)
{
    opnd_t opnd1, opnd2;
    instr_t *instr, *restore, *call;
    
    // return point
    restore = INSTR_CREATE_label(drcontext);

    /* We use the lea + jecxz trick for better performance.
     * lea and jecxz won't disturb the eflags, so we won't need
     * code to save and restore the application's eflags.
     */
    /* lea [reg_cx - buf_end] => reg_cx */
    opnd1 = opnd_create_reg(reg_2);
    opnd2 = OPND_CREATE_MEMPTR(reg_2, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg_cx);
    opnd2 = opnd_create_base_disp(reg_2, reg_cx, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz call */
    call  = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
    //restore = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to our generated lean procedure which performs a full context
     * switch and clean call invocation. This is to reduce the code cache size.
     */
    instrlist_meta_preinsert(ilist, where, call);
    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg_cx);
    /* This is the return address for jumping back from the lean procedure. */
    opnd2 = opnd_create_instr(restore);
    /* We could use instrlist_insert_mov_instr_addr(), but with a register
     * destination we know we can use a 64-bit immediate.
     */
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // return
    instrlist_meta_preinsert(ilist, where, restore);
}



void inline memory_reference_opnd_test(instr_t *instr)
{
    int mem_ref_num, i;

    mem_ref_num = 0;
    for (i = 0; i < instr_num_dsts(instr); i++)
        if (opnd_is_memory_reference(instr_get_dst(instr, i)) == true)
            mem_ref_num++;

    if (mem_ref_num > 1)
        dr_printf("Multi_mem_reference instruction : 0x%08x : 0x%08x\n", instr_get_app_pc(instr), mem_ref_num);
}

void inline base_disp_opnd_test(opnd_t opnd)
{
    if (opnd_is_base_disp(opnd) == false)
        dr_printf("Not base_disp memory_reference_opnd\n");
}

opnd_t inline memory_reference_opnd(instr_t *instr)
{
    int i;

    if (instr_get_app_pc(instr) == NULL)
        dr_printf("FUCK\n");

    for (i = 0; i < instr_num_dsts(instr); i++)
        if (opnd_is_memory_reference(instr_get_dst(instr, i)) == true)
            return instr_get_dst(instr, i);
    
    dr_printf("Memory reference opnd not found : 0x%08x\n", instr_get_app_pc(instr));
    ASSERT(false, "");
}

