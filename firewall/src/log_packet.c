#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_parser.h"

static bool format_icmp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
);
static bool format_tcpudp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
);
static bool format_other_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
);

void log_packet(
    FILE *log_fp,
    const unsigned char *packet,
    FirewallRule *match_rule,
    ActionType policy
)
{
    int fd = -1;

    if (log_fp == NULL || packet == NULL) {
        goto cleanup;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char timestamp[64];
    char log[1024];

    // 現在時刻取得
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local);

    // プロトコル別にログを取得
    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            if (format_icmp_log(packet, log, sizeof(log), timestamp,
                                match_rule, policy) == false) {
                goto cleanup;
            }
            break;
        case IPPROTO_TCP: // TCPはUDPと同じ関数でログを取る
        case IPPROTO_UDP:
            if (format_tcpudp_log(packet, log, sizeof(log), timestamp,
                                  match_rule, policy) == false) {
                goto cleanup;
            }
            break;
        default:
            if (format_other_log(packet, log, sizeof(log), timestamp,
                                 match_rule, policy) == false) {
                goto cleanup;
            }
            break;
    }

    // ファイルに書き込む
    fd = fileno(log_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }
    ssize_t n = fwrite(log, sizeof(char), strlen(log), log_fp);
    if (n == -1) {
        goto cleanup;
    }
    fflush(log_fp);

    cleanup:
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
}

static bool format_icmp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ip_hdr->ihl * 4);
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    unsigned char type = icmp_hdr->type;
    unsigned char code = icmp_hdr->code;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s ICMP %s -> %s [TYPE: %d, CODE: %d] rule:[%s]\n",
        timestamp, action, src_ip, dst_ip, type, code, rule
    );

    return true;
}

static bool format_tcpudp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    char *protocol = (ip_hdr->protocol == IPPROTO_TCP) ? "TCP" : "UDP";
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    get_packet_ports(packet, &src_port, &dst_port);
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s %s %s:%d -> %s:%d rule:[%s]\n",
        timestamp, action, protocol, src_ip, src_port,
        dst_ip, dst_port, rule
    );

    return true;
}

static bool format_other_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    int proto_num = (int)ip_hdr->protocol;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s PROTOCOL NUMBER:%d %s -> %s rule:[%s]\n",
        timestamp, action, proto_num, src_ip, dst_ip, rule
    );

    return true;
}