#ifndef _DELIEVER_PACKAGE_
#define _DELIEVER_PACKAGE_

#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"

extern bool send_safe_memory_block(char *buf, size_t count, bool if_memory_trace);
extern bool send_memory_trace(byte *remote_addr, byte *true_addr, int length);
extern bool send_snapshot(byte *addr, int length);
extern bool send_cpu_snapshot(byte *cpu_snapshot, int length);
extern bool send_fork(byte *addr);

#endif