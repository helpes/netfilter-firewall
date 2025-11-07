#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include "stateful_inspection.h"
#include "packet_handler.h"
#include "judge_packet.h"
#include "log_packet.h"

int handle_input_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
)
{
    PacketHandlerArgs *args = (PacketHandlerArgs *)data;
    pthread_rwlock_t *rwlock = args->rwlock;
    StateTableEntry **head = args->head;
    FirewallRule *rules = NULL;
    size_t rule_count = 0;
    ActionType policy = *(args->policy);
    LogStatus log_flag = *(args->default_logging);
    FILE **log_fp = args->log_fp;
    FirewallRule *match_rule = NULL;

    if (args->fw_rules != NULL) {
        rules = *(args->fw_rules);
    }
    if (args->fw_rule_count != NULL) {
        rule_count = *(args->fw_rule_count);
    }

    // パケットの本体と情報を取得
    unsigned char *packet;
    size_t packet_len = nfq_get_payload(nfa, &packet);
    if (packet_len <= 0) {
        return 0;
    }
    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (packet_hdr == NULL) {
        return 0;
    }
    uint32_t packet_id = ntohl(packet_hdr->packet_id);

    // ルールが存在しないことが判明した時点でパケットをポリシーに従い処理する
    if ((rules == NULL || rule_count == 0) && *head == NULL) {
        if (log_flag == LOG_ENABLED) {
            log_packet(log_fp, packet, match_rule, policy);
        }
        if (policy == ACTION_ACCEPT) {
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
        } else {
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
        }
    }

    // パケットを検証する
    PacketEvalInfo pkt_info = { packet, *head, rules, rule_count, policy };
    PacketResult result = judge_packet(&pkt_info, rwlock);
    if (pkt_info.match_index != -1) { // パケットと一致するルールが存在した
        match_rule = &rules[pkt_info.match_index];
        log_flag = match_rule->log;
    }
    
    if (log_flag == LOG_ENABLED) {
        log_packet(log_fp, packet, match_rule, policy);
    }

    switch (result) {
        case PACKET_ACCEPT:
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
            break; // NOT REACHED
        case PACKET_DROP:
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
        default:
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
    }
}

int handle_output_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
)
{
    PacketHandlerArgs *args = (PacketHandlerArgs *)data;
    pthread_rwlock_t *rwlock = args->rwlock;
    StateTableEntry **head = args->head;
    FirewallRule *rules = NULL;
    size_t rule_count = 0;
    ActionType policy = *(args->policy);
    LogStatus log_flag = *(args->default_logging);
    FILE **log_fp = args->log_fp;
    FirewallRule *match_rule = NULL;

    if (args->fw_rules != NULL) {
        rules = *(args->fw_rules);
    }
    if (args->fw_rule_count != NULL) {
        rule_count = *(args->fw_rule_count);
    }

    // パケットの本体と情報を取得
    unsigned char *packet;
    size_t packet_len = nfq_get_payload(nfa, &packet);
    if (packet_len <= 0) {
        return 0;
    }
    struct nfqnl_msg_packet_hdr *packet_hdr = nfq_get_msg_packet_hdr(nfa);
    if (packet_hdr == NULL) {
        return 0;
    }
    uint32_t packet_id = ntohl(packet_hdr->packet_id);

    // ルールが存在しないことが判明した時点でパケットをポリシーに従い処理する
    if ((rules == NULL || rule_count == 0) && *head == NULL) {
        if (log_flag == LOG_ENABLED) {
            log_packet(log_fp, packet, match_rule, policy);
        }
        if (policy == ACTION_ACCEPT) {
            insert_state_entry(head, packet, rwlock);
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
        } else {
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
        }
    }

    // パケットを検証する
    PacketEvalInfo pkt_info = { packet, *head, rules, rule_count, policy };
    PacketResult result = judge_packet(&pkt_info, rwlock);
    if (pkt_info.match_index != -1) { // パケットと一致するルールが存在した
        match_rule = &rules[pkt_info.match_index];
        log_flag = match_rule->log;
    }

    if (log_flag == LOG_ENABLED) {
        log_packet(log_fp, packet, match_rule, policy);
    }

    switch (result) {
        case PACKET_ACCEPT:
            insert_state_entry(head, packet, rwlock);
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
            break; // NOT REACHED
        case PACKET_DROP:
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
        default:
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
    }
}