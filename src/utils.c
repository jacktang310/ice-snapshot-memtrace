/* ******************************************************************************
 * Copyright (c) 2013-2016 Google, Inc.  All rights reserved.
 * Copyright (c) 2011 Massachusetts Institute of Technology  All rights reserved.
 * Copyright (c) 2008 VMware, Inc.  All rights reserved.
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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "utils.h"
#include "drx.h"
#include <stdio.h>
#ifdef WINDOWS
# include <io.h>
#endif

file_t
log_file_open(client_id_t id, void *drcontext,
              const char *path, const char *name, uint flags)
{
    file_t log;
    char log_dir[MAXIMUM_PATH];
    char buf[MAXIMUM_PATH];
    size_t len;
    char *dirsep;

    DR_ASSERT(name != NULL);
    len = dr_snprintf(log_dir, BUFFER_SIZE_ELEMENTS(log_dir), "%s",
                      path == NULL ? dr_get_client_path(id) : path);
    DR_ASSERT(len > 0);
    NULL_TERMINATE_BUFFER(log_dir);
    dirsep = log_dir + len - 1;
    if (path == NULL /* removing client lib */ ||
        /* path does not have a trailing / and is too large to add it */
        (*dirsep != '/' IF_WINDOWS(&& *dirsep != '\\') &&
         len == BUFFER_SIZE_ELEMENTS(log_dir) - 1)) {
        for (dirsep = log_dir + len;
             *dirsep != '/' IF_WINDOWS(&& *dirsep != '\\');
             dirsep--)
            DR_ASSERT(dirsep > log_dir);
    }
    /* remove trailing / if necessary */
    if (*dirsep == '/' IF_WINDOWS(|| *dirsep == '\\'))
        *dirsep = 0;
    else if (sizeof(log_dir) > (dirsep + 1 - log_dir)/sizeof(log_dir[0]))
        *(dirsep + 1) = 0;
    NULL_TERMINATE_BUFFER(log_dir);
    /* we do not need call drx_init before using drx_open_unique_appid_file */
    log = drx_open_unique_appid_file(log_dir, dr_get_process_id(),
                                     name, "log", flags,
                                     buf, BUFFER_SIZE_ELEMENTS(buf));
    if (log != INVALID_FILE) {
        char msg[MAXIMUM_PATH];
        len = dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg), "Data file %s created", buf);
        DR_ASSERT(len > 0);
        NULL_TERMINATE_BUFFER(msg);
        dr_log(drcontext, LOG_ALL, 1, "%s", msg);
#ifdef SHOW_RESULTS
        DISPLAY_STRING(msg);
# ifdef WINDOWS
        if (dr_is_notify_on()) {
            /* assuming dr_enable_console_printing() is called in the initialization */
            dr_fprintf(STDERR, "%s\n", msg);
        }
# endif /* WINDOWS */
#endif /* SHOW_RESULTS */
    }
    return log;
}

void
log_file_close(file_t log)
{
    dr_close_file(log);
}

FILE *
log_stream_from_file(file_t f)
{
#ifdef WINDOWS
    int fd = _open_osfhandle((intptr_t)f, 0);
    if (fd == -1)
        return NULL;
    return _fdopen(fd, "w");
#else
    return fdopen(f, "w");
#endif
}

void
log_stream_close(FILE *f)
{
    fclose(f); /* closes underlying fd too for all platforms */
}

void* getTEB() {
	void* pTeb;
	__asm
	{
		push eax
		mov eax, fs:[0x18]
			mov pTeb, eax
			pop eax
	}
	return pTeb;
}
 
void* getPEB() {
	void* pPeb;
	__asm
	{
		push eax
		mov eax, fs:[0x30]
			mov pPeb, eax
			pop eax
	}
	return pPeb;
}

bool _page_valid(char *addr)
{
    dr_mem_info_t info = {0};

    dr_query_memory_ex(addr, &info);

    if( (info.type & DR_MEMTYPE_IMAGE || info.type & DR_MEMTYPE_DATA) && (info.prot != DR_MEMPROT_NONE) )
        return true;
    else
        return false;
}

int full_write_file(file_t f,  void* buf, size_t count )
{
    ssize_t written_total = 0;
    ssize_t written_thistime = 0;
    unsigned char* pointer = buf;

    while (written_total < count )
    {
        // dr_printf("[ice_snapshot]: try write  %p, len: %x\n ", pointer + written_total, count- written_total );
        written_thistime = dr_write_file(f, pointer + written_total, count- written_total);
        // dr_printf("[ice_snapshot]: writen: %x\n", written_thistime);

        if (written_thistime == -1) {
            int i;

            DR_TRY_EXCEPT(dr_get_current_drcontext(), 
            {
                i = *(int*)(pointer + written_total);
                dr_printf("[ice_snapshot]: test done : 0x%08x, %d\n", pointer + written_total, i);
            }, {
                dr_mem_info_t info = {0};

                dr_printf("[ice_snapshot]: excetion\n");
                dr_query_memory_ex(pointer + written_total, &info);
                dr_printf("info.type : 0x%x\n", info.type);
                dr_printf("info.prot : 0x%x\n", info.prot);
            });
        }

        written_total += written_thistime;
    }

    return 0;
}