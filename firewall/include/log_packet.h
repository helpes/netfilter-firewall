#ifndef LOG_PACKET_H
#define LOG_PACKET_H

#include <stdio.h>
#include "firewall_config.h"

void log_packet(
    FILE **log_fp,
    const unsigned char *packet,
    FirewallRule *match_rule,
    ActionType policy
);

#endif