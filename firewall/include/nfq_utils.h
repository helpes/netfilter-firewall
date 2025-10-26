#ifndef NFQ_UTILS_H
#define NFQ_UTILS_H

#include <stdio.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "firewall_config.h"

int create_nfq_socket(struct nfq_handle **h);
struct nfq_q_handle *create_nfq_queue_handle(
    struct nfq_handle *h,
    int queue_num,
    nfq_callback *callback,
    void *callback_args
);
void destroy_nfq_queues(struct nfq_q_handle *q_handles[], size_t q_handle_len);

#endif