#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stdio.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "firewall_config.h"

typedef struct {
    FILE *log_fp;
    FirewallRule **fw_rules;
    size_t *fw_rule_count;
    ActionType *policy;
} PacketHandlerArgs;

int handle_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
);

#endif