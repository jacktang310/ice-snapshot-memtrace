#ifndef _ICE_SNAPSHOT_
#define _ICE_SNSPSHOT_

#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"

#include "range_manager.h"

//#define FILE
#define SOCKET

#define MEM_TRACE

extern module_data_t *appmod;
extern range_manager_t manager;
extern file_t output_file;

#endif