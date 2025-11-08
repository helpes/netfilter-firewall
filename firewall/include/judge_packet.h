#ifndef JUDGE_PACKET_H
#define JUDGE_PACKET_H

#include <pthread.h>
#include "firewall_config.h"
#include "stateful_inspection.h"

typedef enum {
    PACKET_ACCEPT,
    PACKET_DROP
} PacketResult;

typedef struct {
    unsigned char *packet;
    StateTableEntry *head;
    FirewallRule *rules;
    size_t rule_count;
    ActionType policy;
    int match_index; // -1はパケットと一致するルールが存在しない
} PacketEvalInfo;

PacketResult judge_packet(PacketEvalInfo *pkt_info, pthread_rwlock_t *rwlock);

#endif