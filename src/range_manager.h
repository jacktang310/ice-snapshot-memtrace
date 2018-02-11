#ifndef _RANGE_MANAGER_
#define _RANGE_MANAGER_


#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"

#include "hashtable.h"


typedef struct _range_manager_t {
    hashtable_t table;
    hashtable_t lookback_table;

    void (*free_callback)(byte *range_begin, byte *range_end);
    int size;

    void *mutex;
} range_manager_t;

extern bool range_manager_init(range_manager_t * manager);
extern void range_manager_set_free_callback(range_manager_t *manager, 
                                         void (*free_callback)(byte *range_begin, byte *range_end));
extern void range_manager_delete(range_manager_t *manager);

extern bool range_manager_add(range_manager_t *manager, char *range_begin, int size);
extern void range_manager_dump(range_manager_t *manager);


#endif