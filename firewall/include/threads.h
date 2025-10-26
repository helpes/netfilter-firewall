#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "firewall_config.h"

typedef struct {
    pthread_rwlock_t *rw_lock;
    struct nfq_handle *h;
} NfqHandlerArgs;

typedef struct {
    pthread_rwlock_t *rw_lock;
    int domain_sock;
    char *config_file;
    char *rule_file;
    FirewallConfig *config;
    FirewallRule **input_rules;
    FirewallRule **output_rules;
    RuleCounts *rule_counts;
} CmdListenerArgs;

void *nfq_handler_thread(void *arg);
void *command_listener_thread(void *arg);

#endif