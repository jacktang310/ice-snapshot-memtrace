#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"

#include "ice_snapshot.h"
#include "deliever_package.h"
#include "package.h"

#include "windows.h"

// #define SOCKET
// #define FILE

extern file_t output_file;

#ifdef FILE
bool send(byte *buf, int count)
{
    if (count != -1)
        full_write_file(output_file, buf, count);
    // send_by_socket(buf, count);
    return true;
}
#endif

#ifdef SOCKET

bool is_addr_file_exist = false;
int* g_addr_mem = NULL;
void print_memory_status(){ 
    dr_printf("[Client] g_addr_mem[0] = %x\n", g_addr_mem[0]);
    dr_printf("[Client] g_addr_mem[1] = %x\n", g_addr_mem[1]);
    dr_printf("[Client] g_addr_mem[2] = %x\n", g_addr_mem[2]);
}

void share_address_memory(){
    //memory that replace the D:\\output\\addr_drrun.mem ; we just store one fix address in the file 
    char address_filename[] = "C:\\output\\addr_drrun.mem";
    file_t f;
    int * addr_mem = (int*)dr_global_alloc(3 * sizeof(int));
    if (addr_mem){
        is_addr_file_exist = true;
        g_addr_mem = addr_mem;
        f = dr_open_file(address_filename, DR_FILE_WRITE_OVERWRITE);
        dr_write_file(f, &addr_mem, sizeof(addr_mem));
        dr_close_file(f);
        memset(g_addr_mem, 0xffffffff, 3 * sizeof(int));
        print_memory_status();
    }
    
}

// interface
// please redirect
bool send(byte* buf, int count)
{

    //dr_printf("send memory at 0x%08x : 0x%08x\n", addr, length);
    int number = count;
    int flag = 0;  // sync with drrun.exe , 0 -> client write file done ; 1 - > drrun read memory done
    char address_filename[] = "C:\\output\\addr_drrun.mem";
    int i;
    int tmp;

    // send_by_file(buf, count);
    if (is_addr_file_exist == false){
        share_address_memory();
    }

    dr_printf("[Client]  memory address = %08x \n ", buf);
    dr_printf("[Client] allocate memory size = %d \n", count);
    dr_printf("[Client] allocate memory content = kkkkk \n");
    
    /*
    tmp = count;
    if (count > 100)
    {
        tmp = 10;
    }
    for (i = 0; i < tmp; ++i){
	    dr_printf("%x ", buf[i]);
    }
    
    dr_printf("\n");
    */
    
    while (true){
        //print_memory_status();

	    int pre_alloc_addr, pre_alloc_count, cur_flag;

	    if (g_addr_mem[2] == 0xffffffff){
		    dr_printf("[Client] the first time to %x \n ", g_addr_mem);
		    break;
	    }

        pre_alloc_addr = g_addr_mem[0];
        pre_alloc_count = g_addr_mem[1];
        cur_flag = g_addr_mem[2];
        

        if (cur_flag == 1){
            dr_printf("[Client] Drrun set flag success!\n");
		    break;
	    }
	    else{
		    //dr_printf("[Client] client sleep in while for 0.1 second \n ");
		    Sleep(1);
	    }
    }

    g_addr_mem[0] = buf;
    g_addr_mem[1] = count;
    g_addr_mem[2] = 0;
    //print_memory_status();
    dr_printf("_____________________________________________________________________________________________\n");

    return true;
}
#endif
bool page_valid(char *addr)
{
    dr_mem_info_t info = {0};

    dr_query_memory_ex(addr, &info);

    if( (info.type & DR_MEMTYPE_IMAGE || info.type & DR_MEMTYPE_DATA) && (info.prot != DR_MEMPROT_NONE) )
        return true;
    else
        return false;
}

// static bool page_valid(char *addr)
// {
//     char chr;
//     bool valid;

//     DR_TRY_EXCEPT(dr_get_current_drcontext(),
//     {
//         chr = *addr;
//         valid = true;
//     }, {
//         valid = false;
//         dr_printf("invalid page............................................\n");
//     });

//     return valid;
// }

// extern bool safe_send_memory_block(char* buf, size_t count, bool if_memory_trace)
// {
//     byte *buf_end = buf + count;
//     byte *ptr = buf;
//     byte *cur_block = ptr;

//     bool current_block_valid = false;

//     // dr_printf("dump 0x%08x : 0x%08x\n", buf, count);

//     while (ptr < buf_end) {
//         if (current_block_valid == false && page_valid(ptr) == true) {
//             cur_block = ptr;
//             current_block_valid = true;
//          } else if (current_block_valid == true && page_valid(ptr) == false) {
//             if (if_memory_trace) {
//                 send_memory_trace(cur_block, cur_block, ptr - cur_block);
//             } else {
//                 send_snapshot(cur_block, ptr - cur_block);
//             }
//             current_block_valid = false;
//         }

//         // update ptr
//         ptr += 0x1000;
//     }

//     if (current_block_valid == true) {
//         if (if_memory_trace)
//             send_memory_trace(cur_block, cur_block, buf_end - cur_block);
//         else
//             send_snapshot(cur_block, buf_end - cur_block);
//     }

//     return true;
// }

int safe_send_memory_block(void* buf, size_t count, bool if_memory_trace)
{
    dr_mem_info_t info = {0};
    size_t read_count = 0;
    unsigned char* p = buf;
    unsigned char* p_old = buf;
    unsigned int tmp = 0;
    char filename[0x100] = {0};
    file_t f;
    unsigned int loc = ( unsigned int) buf;

    // unsigned char tmp_buf[1024] = {0};
    // memcpy(tmp_buf, p, 0x4);

    if(count <= 0x1000)
    {
        // dr_snprintf(filename, 0x100,"output\\%x_%x.mem",loc , 0);

        // f = dr_open_file(filename, DR_FILE_WRITE_OVERWRITE);


        // if (f == INVALID_FILE)
        // {
        // dr_printf("dr_open_file(%s) fail\n", filename);
        // }


        // dr_write_file(f,  &loc, sizeof(loc));

        // dr_write_file(f,  &count, sizeof(count));

        // full_write_file(f, buf, count);

        // dr_close_file(f);
        
        if (if_memory_trace)
            send_memory_trace(buf, buf, count);
        else
            send_snapshot(buf, count);
    }
    else
    {
        int break_flag = 0;

        unsigned int prev_read_count = 0;

        unsigned char* p_write_prev = 0;
        unsigned int len_write_prev = 0;


        while(read_count< count)
        {

            if(count - read_count < 0x1000)
            {
                    tmp = count - read_count;
            }
            else
            {
                    tmp = 0x1000;
            }
            


            dr_query_memory_ex(p + read_count, &info);

            
            #if JACK_FILE_DEBUG
            dr_printf("current address: %p: info: base_pc: %p size: %x, prot: %x, type: %x\n", p + read_count, info.base_pc, info.size,  info.prot, info.type);
            #endif


            if( (info.type & DR_MEMTYPE_IMAGE || info.type & DR_MEMTYPE_DATA) && (info.prot != DR_MEMPROT_NONE) && (info.prot & DR_MEMPROT_READ) )
            //if( info.prot &  DR_MEMPROT_READ)
            {
                #if JACK_FILE_DEBUG     
                 dr_printf("jack: not break\n");
               #endif

                if(break_flag == 1)
                {
                    #if JACK_FILE_DEBUG  
                    dr_printf("jack: one save region begin\n");
                    #endif

                    break_flag = 0;
                    p_old = p + read_count;
                    prev_read_count = tmp;

                    
                }
                else
                {
                    prev_read_count += tmp;
                }
               
                
            }
            else
            {
                unsigned int new_pointer = (unsigned int)(p_old );

                #if JACK_FILE_DEBUG 
               dr_printf("jack: break\n");
               #endif

               if(p_write_prev == p_old && len_write_prev == prev_read_count) 
               {

               }
               else
               {

                    // dr_snprintf(filename, 0x100,"output\\%x_%x.mem",loc , new_pointer);

                    //  f = dr_open_file(filename, DR_FILE_WRITE_OVERWRITE);

                    // if (f == INVALID_FILE)
                    // {
                    //     dr_printf("dr_open_file(%s) fail\n", filename);
                    // }

                    // dr_write_file(f,  &new_pointer, sizeof(new_pointer));

                    // dr_write_file(f,  &prev_read_count, sizeof(prev_read_count));

                    // dr_printf("full_write_file: addr: %p ,  len: %x\n",  p_old, prev_read_count);
                 
                    // full_write_file(f, p_old , prev_read_count);

                    // dr_close_file(f);
                    if (if_memory_trace)
                        send_memory_trace(p_old, p_old, prev_read_count);
                    else
                        send_snapshot(p_old, prev_read_count);

                    p_write_prev = p_old;

                    len_write_prev = prev_read_count;
                    
               }

               break_flag = 1;
            }
            
                
            read_count+=tmp;
        }

        if (prev_read_count && !(p_write_prev == p_old && len_write_prev == prev_read_count))
        {

             unsigned int new_pointer = (unsigned int)(p_old );


                // dr_snprintf(filename, 0x100,"output\\%x_%x.mem",loc , new_pointer);

                // f = dr_open_file(filename, DR_FILE_WRITE_OVERWRITE);

                // if (f == INVALID_FILE)
                // {
                //     dr_printf("dr_open_file(%s) fail\n", filename);
                // }

                // dr_write_file(f,  &new_pointer, sizeof(new_pointer));


                // dr_write_file(f,  &prev_read_count, sizeof(prev_read_count));


                // dr_printf("full_write_file: addr: %p ,  len: %x\n",  p_old, prev_read_count);
                //  full_write_file(f, p_old , prev_read_count);

                // dr_close_file(f);
                if (if_memory_trace)
                    send_memory_trace(p_old, p_old, prev_read_count);
                else
                    send_snapshot(p_old, prev_read_count);

        }


       
    }

    return 0;

}


int safe_send_memory_block2(char* buf, size_t count, bool if_memory_trace)
{
    dr_mem_info_t info = {0};
    size_t read_count = 0;
    unsigned char* p = buf;
    unsigned char* p_old = buf;
    unsigned int tmp = 0;
    char filename[0x100] = {0};
    file_t f;
    unsigned int loc = ( unsigned int) buf;

    unsigned char tmp_buf[1024] = {0};

    memcpy(tmp_buf, p, 0x4);


    if(count <= 0x1000)
    {
        dr_printf("[instrace]: write file : 0x%08x : 0x%08x\n", loc, 0);
        if (if_memory_trace)
            send_memory_trace(buf, buf, count);
        else
            send_snapshot(buf, count);
    }
    else
    {
        int break_flag = 0;

        unsigned int prev_read_count = 0;

        unsigned char* p_write_prev = 0;
        unsigned int len_write_prev = 0;


        while(read_count< count)
        {

            if(count - read_count < 0x1000)
            {
                    tmp = count - read_count;
            }
            else
            {
                    tmp = 0x1000;
            }
            


            dr_query_memory_ex(p + read_count, &info);

            
            #if JACK_FILE_DEBUG
            dr_printf("[instrace]: current address: %p: info: base_pc: %p size: %x, prot: %x, type: %x\n", p + read_count, info.base_pc, info.size,  info.prot, info.type);
            #endif


            if( (info.type & DR_MEMTYPE_IMAGE || info.type & DR_MEMTYPE_DATA) && (info.prot != DR_MEMPROT_NONE) )
            //if( info.prot &  DR_MEMPROT_READ)
            {
                #if JACK_FILE_DEBUG     
                 dr_printf("jack: not break\n");
               #endif

                if(break_flag == 1)
                {
                    #if JACK_FILE_DEBUG  
                    dr_printf("jack: one save region begin\n");
                    #endif

                    break_flag = 0;
                    p_old = p + read_count;
                    prev_read_count = tmp;

                    
                }
                else
                {
                    prev_read_count += tmp;
                }
               
                
            }
            else
            {
                unsigned int new_pointer = (unsigned int)(p_old );

                #if JACK_FILE_DEBUG 
               dr_printf("jack: break\n");
               #endif

               if(p_write_prev == p_old && len_write_prev == prev_read_count) 
               {

               }
               else
               {

                    dr_printf("[instrace]: write file : 0x%08x 0x%08x\n", p_old , new_pointer);

                if (if_memory_trace)
                    send_memory_trace(p_old, p_old, prev_read_count);
                else
                    send_snapshot(p_old, prev_read_count);

                    p_write_prev = p_old;

                    len_write_prev = prev_read_count;
                    
               }

               break_flag = 1;
            }
            
                
            read_count+=tmp;
        }

        if (prev_read_count && !(p_write_prev == p_old && len_write_prev == prev_read_count))
        {

             unsigned int new_pointer = (unsigned int)(p_old );


                dr_printf("[instrace]: write file : 0x%08x 0x%08x\n",loc , new_pointer);

                if (if_memory_trace)
                    send_memory_trace(p_old, p_old, prev_read_count);
                else
                    send_snapshot(p_old, prev_read_count);

        }


       
    }

    return 0;

}



//////////////////////////////////////////////////////////////////////////
extern bool send_memory_trace(byte *remote_addr, byte *true_addr, int length)
{
    package_header header;

    // DR_TRY_EXCEPT(dr_get_current_drcontext(), 
    {
        dr_mem_info_t info = {0};
        dr_query_memory_ex(true_addr, &info);
        if(!( (info.type & DR_MEMTYPE_IMAGE || info.type & DR_MEMTYPE_DATA) && (info.prot != DR_MEMPROT_NONE) ) ) {
            dr_printf("[ice_snapshot]: invalid memory trace at 0x%08x\n", remote_addr);
            return false;
        }
    }


        // int i = *(int*)true_addr;
        // dr_printf("[ice_snapshot]: test done : 0x%08x, %d\n", pointer + written_total, i);
    // }, {
    //     dr_printf("[ice_snapshot]: invalid page\n");
    //     return false;
    // });

    dr_printf("[ice_snapshot]: send memory_trace package from 0x%08x : 0x%08x\n", remote_addr, length);

    header.code = P_MEMORY_TRACE;
    header.length = sizeof(remote_addr) + sizeof(length) + length;
    send(&header, sizeof(header));

    send(&remote_addr, sizeof(remote_addr));
    send(&length, sizeof(length));
    send(true_addr, length);
    SEND_END_OF_PACKAGE;

    return true;
}

extern bool send_snapshot(byte *addr, int length)
{
    package_header header;

    dr_printf("[ice_snapshot]: send snapshot package from 0x%08x : 0x%08x\n", addr, length);

    header.code = P_SNAPSHOT;
    header.length = length + sizeof(addr) + sizeof(length);
    send(&header, sizeof(header));

    send(&addr, sizeof(addr));
    send(&length, sizeof(length));
    send(addr, length);
    SEND_END_OF_PACKAGE;

    return true;
}

extern bool send_cpu_snapshot(byte *cpu_snapshot, int length)
{
    package_header header;

    dr_printf("[ice_snapshot]: send cpu_snapshot package\n");

    header.code = P_CPU_SNAPSHOT;
    header.length = length;
    send(&header, sizeof(header));

    send(cpu_snapshot, length);
    SEND_END_OF_PACKAGE;

    return true;
}

extern bool send_fork(byte *addr)
{
    package_header header;
    app_pc target_pc = addr;

    dr_printf("[ice_snapshot]: send fork package : 0x%08x\n", addr);

    header.code = P_FORK;
    header.length = sizeof(target_pc);
    send(&header, sizeof(header));
    send(&target_pc, sizeof(target_pc));

    SEND_END_OF_PACKAGE;

    return true;
}
