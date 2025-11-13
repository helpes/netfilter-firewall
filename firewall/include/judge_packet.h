#ifndef JUDGE_PACKET_H
#define JUDGE_PACKET_H

#include "firewall_config.h"

typedef enum {
    PACKET_ACCEPT,
    PACKET_DROP
} PacketResult;

typedef struct {
    unsigned char *packet;
    FirewallRule *rules;
    size_t rule_count;
    ActionType policy;
    int match_index; // -1はパケットと一致するルールが存在しない
} PacketEvalInfo;

PacketResult judge_packet(PacketEvalInfo *pkt_info);

#endif