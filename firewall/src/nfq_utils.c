#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int create_nfq_socket(struct nfq_handle **h)
{
    if (h == NULL) {
        errno = EINVAL;
        return -1;
    }

    *h = nfq_open();
    if (*h == NULL) {
        return -1;
    }

    if (nfq_bind_pf(*h, AF_INET) == -1) {
        nfq_close(*h);
        return -1;
    }

    return nfq_fd(*h);
}

struct nfq_q_handle *create_nfq_queue_handle(
    struct nfq_handle *h,
    int queue_num,
    nfq_callback *callback,
    void *callback_args
)
{
    if (h == NULL || callback == NULL || callback_args == NULL) {
        errno = EINVAL;
        return NULL;
    }

    struct nfq_q_handle *qh = nfq_create_queue(
        h, queue_num, callback, callback_args
    );
    if (qh == NULL) {
        return NULL;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xFFFF) == -1) {
        nfq_destroy_queue(qh);
        return NULL;
    }

    return qh;
}

void destroy_nfq_queues(struct nfq_q_handle *q_handles[], size_t q_handle_len)
{
    for (int i = 0; i < q_handle_len; i++) {
        if (q_handles[i] != NULL) {
            nfq_destroy_queue(q_handles[i]);
        }
    }
}