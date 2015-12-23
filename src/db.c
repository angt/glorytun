#include "db.h"
#include "common-static.h"

#define CBIT(X)      (1&(intptr_t)(X))
#define CBIT_PTR(X)  (uint8_t *)(1|(intptr_t)(X))
#define CBIT_NODE(X) (struct node *)(1^(intptr_t)(X))

struct node {
    uint8_t *child[2];
    uint8_t size;
    uint8_t mask;
};

static inline size_t db_size (const uint8_t *a)
{
    return (a[0]?:str_len((char *)a+1))+1;
}

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

static inline int db_dir (struct node *node, const uint8_t *data, const size_t size)
{
    if (node->size>=size)
        return 0;

    return (node->mask|data[node->size])==255;
}

uint8_t *db_search (uint8_t **p, uint8_t *data)
{
    if (!*p)
        return NULL;

    uint8_t *r = *p;
    const size_t size = db_size(data);

    while (CBIT(r)) {
        struct node *node = CBIT_NODE(r);
        r = node->child[db_dir(node, data, size)];
    }

    if (!db_cmp(r, data))
        return r;

    return NULL;
}

int db_insert (uint8_t **p, uint8_t *data)
{
    if (CBIT(data))
        return 0;

    if (!*p) {
        *p = data;
        return 1;
    }

    uint8_t *r = *p;
    size_t data_size = db_size(data);

    while (CBIT(r)) {
        struct node *node = CBIT_NODE(r);
        r = node->child[db_dir(node, data, data_size)];
    }

    const size_t diff = db_cmp(r, data);

    if (!diff)
        return 2;

    const uint8_t size = diff-1;
    const uint8_t mask = ~((1u<<31)>>CLZ(r[size]^data[size]));

    while (CBIT(*p)) {
        struct node *node = CBIT_NODE(*p);

        if ((node->size>size) ||
            (node->size==size && node->mask>mask)) {
            break;
        }

        p = node->child+db_dir(node, data, data_size);
    }

    struct node *node = malloc(sizeof(struct node));

    if (!node)
        return 0;

    const int dir = (mask|r[size])==255;

    node->child[dir] = *p;
    node->child[1-dir] = data;
    node->size = size;
    node->mask = mask;

    *p = CBIT_PTR(node);

    return 1;
}

int db_delete (uint8_t **p, uint8_t *data)
{
    if (!*p)
        return 0;

    uint8_t **p_old = NULL;
    struct node *node = NULL;
    int dir = 0;

    const size_t size = db_size(data);

    while (CBIT(*p)) {
        p_old = p;
        node = CBIT_NODE(*p);
        dir = db_dir(node, data, size);
        p = node->child+dir;
    }

    if (db_cmp(data, *p))
        return 0;

    free(*p);

    if (!p_old) {
        *p = NULL;
        return 1;
    }

    *p_old = node->child[1-dir];
    free(node);

    return 1;
}
