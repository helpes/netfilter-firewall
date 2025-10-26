#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "judge_packet.h"
#include "firewall_config.h"
#include "firewall_parser.h"


PacketResult judge_packet(PacketEvalInfo *pkt_info)
{
    unsigned char *packet = pkt_info->packet;
    FirewallRule *rules = pkt_info->rules;
    size_t rule_count = pkt_info->rule_count;
    ActionType policy = pkt_info->policy;
    pkt_info->match_index = -1;

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    ProtocolType protocol = get_protocol_from_number(ip_hdr->protocol);
    char src_ip[IP_ADDR_MAX_LEN];
    char dst_ip[IP_ADDR_MAX_LEN];
    int src_port;
    int dst_port;

    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return PACKET_DROP;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return PACKET_DROP;
    }
    if (get_packet_ports(packet, &src_port, &dst_port) == false) {
        return PACKET_DROP;
    }

    // パケットとルールを一つずつ比較
    for (int i = 0; i < rule_count; i++) {
        if (protocol != rules[i].protocol && rules[i].protocol != PROTO_ANY) {
            continue;
        }
        if (strcmp(src_ip, rules[i].src_ip) != 0 &&
            strcmp(rules[i].src_ip, "ANY") != 0) {
            continue;
        }
        if (strcmp(dst_ip, rules[i].dst_ip) != 0 &&
            strcmp(rules[i].dst_ip, "ANY") != 0) {
            continue;
        }
        if (src_port != rules[i].src_port && rules[i].src_port != -1) {
            continue;
        }
        if (dst_port != rules[i].dst_port && rules[i].dst_port != -1) {
            continue;
        }
        if (rules[i].state != RULE_ENABLED) {
            break;
        }

        pkt_info->match_index = i;
        return (rules[i].action == ACTION_ACCEPT) ? PACKET_ACCEPT : PACKET_DROP;
    }

    // どのルールにもマッチしなければポリシーに従う
    return (policy == ACTION_ACCEPT) ? PACKET_ACCEPT : PACKET_DROP;
}