#include "common.h"

#include "db.h"
#include "str.h"

#define CBIT(X)      (1&(intptr_t)(X))
#define CBIT_PTR(X)  (uint8_t *)(1|(intptr_t)(X))
#define CBIT_NODE(X) (struct node *)(1^(intptr_t)(X))

struct node {
    uint8_t *child[2];
    uint32_t point;
};

_pure_
static inline size_t db_size (const uint8_t *a)
{
    return (a[0]?:str_len((char *)a+1))+1;
}

_pure_
static inline size_t db_cmp (const uint8_t *a, const uint8_t *b)
{
    const size_t size = a[0];

    if (size!=b[0])
        return 1;

    if (!size) {
        size_t i = str_cmp((char *)a+1, (char *)b+1);
        return i?i+1:0;
    }

    for (size_t i=1; i<=size; i++) {
        if (a[i]!=b[i])
            return i+1;
    }

    return 0;
}

_pure_
static inline int db_dir (const uint32_t point, uint8_t *data, const size_t size)
{
    const size_t pos = point>>8;

    if (pos>=size)
        return 0;

    return ((point|data[pos])&255)==255;
}

uint8_t *db_search (uint8_t **p, uint8_t *data)
{
    if _0_(!*p)
        return NULL;

    uint8_t *r = *p;
    const size_t size = db_size(data);

    while (CBIT(r)) {
        struct node *node = CBIT_NODE(r);
        r = node->child[db_dir(node->point, data, size)];
    }

    if (!db_cmp(r, data))
        return r;

    return NULL;
}

uint8_t *db_insert (uint8_t **p, uint8_t *data)
{
    if _0_(CBIT(data))
        return NULL;

    if _0_(!*p) {
        *p = data;
        return data;
    }

    uint8_t *r = *p;
    size_t size = db_size(data);

    while (CBIT(r)) {
        struct node *node = CBIT_NODE(r);
        r = node->child[db_dir(node->point, data, size)];
    }

    const size_t diff = db_cmp(r, data);

    if _0_(!diff)
        return r;

    const size_t pos = diff-1;
    const uint8_t mask = ~((1u<<31)>>CLZ(r[pos]^data[pos]));
    const size_t point = (pos<<8)|mask;

    while (CBIT(*p)) {
        struct node *node = CBIT_NODE(*p);

        if (node->point>point)
            break;

        p = node->child+db_dir(node->point, data, size);
    }

    struct node *node = malloc(sizeof(struct node));

    if _0_(!node)
        return NULL;

    const int dir = (mask|r[pos])==255;

    node->child[dir] = *p;
    node->child[1-dir] = data;
    node->point = point;

    *p = CBIT_PTR(node);

    return data;
}

uint8_t *db_remove (uint8_t **p, uint8_t *data)
{
    if _0_(!*p)
        return NULL;

    const size_t size = db_size(data);

    uint8_t **p_old = NULL;
    struct node *node = NULL;
    int dir = 0;

    while (CBIT(*p)) {
        p_old = p;
        node = CBIT_NODE(*p);
        dir = db_dir(node->point, data, size);
        p = node->child+dir;
    }

    if _0_(db_cmp(data, *p))
        return NULL;

    uint8_t *r = *p;

    if (p_old) {
        *p_old = node->child[1-dir];
        free(node);
    } else {
        *p = NULL;
    }

    return r;
}
