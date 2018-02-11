#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"

#include "hashtable.h"

#include "utils.h"
#include "range_manager.h"

void * __hashtable_add_replace(hashtable_t *table, void *key, void *payload);

static void range_manager_free_callback(range_manager_t * manager, byte *range_begin, byte *range_end)
{
    // char *range_begin, *range_end;

    if (manager->free_callback == NULL)
        return;

    // range_end = payload;
    // range_begin = hashtable_lookup(&(manager->lookback_table), range_end);
    // ASSERT(range_begin != NULL, "");
    // ASSERT(range_begin < range_end, "");
    // if (range_begin == NULL || range_begin > range_end) {
    //     dr_printf("ERROR range from 0x%08x to 0x%08x\n", range_begin, range_end);
    //     ASSERT(false, "");
    // }

    // if (range_end - range_begin > 0x1000000)
    //     dr_printf("[ice_snapshot]: FUCK : ragne_begin : 0x%08x, range_end : 0x%08x-------------------------------------\n", range_begin, range_end);

    manager->free_callback(range_begin, range_end);
}

bool range_manager_init(range_manager_t *manager)
{
    hashtable_init(&(manager->table), 13, HASH_INTPTR, false);
    hashtable_init(&(manager->lookback_table), 13, HASH_INTPTR, false);

    manager->mutex = dr_mutex_create();

    manager->free_callback = NULL;
    manager->size = 0;

    return true;
}

void range_manager_set_free_callback(range_manager_t *manager,
                                    void (*free_callback)(byte *range_begin, byte *range_end))
{
    manager->free_callback = free_callback;
}

void range_manager_delete(range_manager_t *manager)
{
    hashtable_delete(&(manager->table));
    hashtable_delete(&(manager->lookback_table));

    // dr_mutex_unlock(manager->mutex);
    dr_mutex_destroy(manager->mutex);
}

bool range_manager_add(range_manager_t *manager, char *range_begin, char *range_end)
{
    char *old_range_end, *next_range_end;
    char *left_entry, *right_entry;


    dr_mutex_lock(manager->mutex);

    left_entry = range_begin;
    right_entry = range_end;

    old_range_end = hashtable_lookup(&(manager->table), range_begin);
    if (old_range_end != NULL) {
        if (old_range_end >= range_end) {
            goto done;
        }
        // merge with current range
        manager->size--;
    } else {
        // merge with last range
        char *last_range_begin;
        last_range_begin = hashtable_lookup(&(manager->lookback_table), range_begin);
        if (last_range_begin != NULL && 
            // 因为lookback_table省去了很多删除操作 因此要在table里验证一下last_range
            // 是否存在
            hashtable_lookup(&(manager->table), last_range_begin) == range_begin){
            left_entry = last_range_begin;
            manager->size--;
        }
    }

    // merge with next range
    next_range_end = hashtable_lookup(&(manager->table), range_end);
    if (next_range_end != NULL){
        hashtable_remove(&(manager->table), range_end);

        right_entry = next_range_end;
        manager->size--;
    }

    __hashtable_add_replace(&(manager->table), left_entry, right_entry);
    __hashtable_add_replace(&(manager->lookback_table), right_entry, left_entry);

    manager->size++;

done:
    dr_mutex_unlock(manager->mutex);

    return true;
}

int inline range_manager_size(range_manager_t *manager)
{
    return manager->size;
}


//////////////////////////////////////////////////////////////////////////////////////////////
////////  modified from ext/drcontainers/hashtable.c

#define HASHTABLE_SIZE(num_bits) (1U << (num_bits))
#define HASH_MASK(num_bits) ((~0U)>>(32-(num_bits)))
#define HASH_FUNC_BITS(val, num_bits) ((val) & (HASH_MASK(num_bits)))

void range_manager_dump(range_manager_t *manager)
{
    hashtable_t *table = &(manager->table);
    int i;

    dr_printf("[ice_snapshot]: Dumping range manager : %d\n", manager->size);

    dr_mutex_lock(manager->mutex);

    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        hash_entry_t *e = table->table[i];
        while (e != NULL) {
            hash_entry_t *nexte = e->next;
            // range_manager_free_callback(manager, e->payload);
            range_manager_free_callback(manager, e->key, e->payload);
            dr_global_free(e, sizeof(*e));
            e = nexte;
        }
        table->table[i] = NULL;
    }
    table->entries = 0;

    dr_mutex_unlock(manager->mutex);
}

/////// need by hashtable_add_replace
static uint
hash_key(hashtable_t *table, void *key)
{
    uint hash = 0;
    if (table->hash_key_func != NULL) {
        hash = table->hash_key_func(key);
    } else {
        /* HASH_INTPTR, or fallback for HASH_CUSTOM in release build */
        // ASSERT(table->hashtype == HASH_INTPTR,
            //    "hashtable.c hash_key internal error: invalid hash type");
        hash = (uint)(ptr_uint_t) key;
    }
    return HASH_FUNC_BITS(hash, table->table_bits);
}

static bool
keys_equal(hashtable_t *table, void *key1, void *key2)
{
    if (table->cmp_key_func != NULL)
        return table->cmp_key_func(key1, key2);
    else {
        /* HASH_INTPTR, or fallback for HASH_CUSTOM in release build */
        // ASSERT(table->hashtype == HASH_INTPTR,
            //    "hashtable.c keys_equal internal error: invalid hash type");
        return key1 == key2;
    }
}

static bool
__hashtable_check_for_resize(hashtable_t *table)
{
    size_t capacity = (size_t) HASHTABLE_SIZE(table->table_bits);
    if (table->config.resizable &&
        /* avoid fp ops.  should check for overflow. */
        table->entries * 100 > table->config.resize_threshold * capacity) {
        hash_entry_t **new_table;
        size_t new_sz;
        uint i, old_bits;
        /* double the size */
        old_bits = table->table_bits;
        table->table_bits++;
        new_sz = (size_t) HASHTABLE_SIZE(table->table_bits) * sizeof(hash_entry_t*);
        new_table = (hash_entry_t **) dr_global_alloc(new_sz);
        memset(new_table, 0, new_sz);
        /* rehash the old table into the new */
        for (i = 0; i < HASHTABLE_SIZE(old_bits); i++) {
            hash_entry_t *e = table->table[i];
            while (e != NULL) {
                hash_entry_t *nexte = e->next;
                uint hindex = hash_key(table, e->key);
                e->next = new_table[hindex];
                new_table[hindex] = e;
                e = nexte;
            }
        }
        dr_global_free(table->table, capacity * sizeof(hash_entry_t*));
        table->table = new_table;
        return true;
    }
    return false;
}

// 原本的 hashtable_add_replace 有可能会卡住，所以稍微改了一下
// check_for_resize没有变动，但是因为这个api没有导出，又不想对原本的dynamorio做太大改动
// 所以复制了一份过来
static void *
__hashtable_add_replace(hashtable_t *table, void *key, void *payload)
{
    void *old_payload = NULL;
    uint hindex = hash_key(table, key);
    hash_entry_t *e, *new_e = NULL;
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex]; e != NULL; e = e->next) {
        if (keys_equal(table, e->key, key)) {
            new_e = e;

            break;
        }
    }

    if (new_e == NULL) {
        new_e = dr_global_alloc(sizeof(*new_e));
        new_e->key = key;

        new_e->next = table->table[hindex];
        table->table[hindex] = new_e;
        table->entries++;
        __hashtable_check_for_resize(table);
    }

    new_e->payload = payload;

    if (table->synch)
        dr_mutex_unlock(table->lock);
    return old_payload;
}