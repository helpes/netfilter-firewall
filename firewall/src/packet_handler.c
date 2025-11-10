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

    // ステートテーブルからパケットを検証する
    pthread_rwlock_wrlock(rwlock);
    PacketResult result = PACKET_DROP;
    StateTableEntry *match_entry = lookup_state_table(*head, packet);
    if (match_entry != NULL) {
        if (check_entry_timeout(match_entry) == true) {
            delete_entry(head, match_entry);
        } else {
            match_entry->last_activity = time(NULL);
            result = PACKET_ACCEPT;
        }
    }
    pthread_rwlock_unlock(rwlock);

    if (result == PACKET_DROP) {
        // ルールからパケットを検証する
        pthread_rwlock_rdlock(rwlock);
        PacketEvalInfo pkt_info = { packet, rules, rule_count, policy };
        result = judge_packet(&pkt_info);
        if (pkt_info.match_index != -1) { // パケットと一致するルールが存在した場合
            match_rule = &rules[pkt_info.match_index];
            log_flag = match_rule->log;
        }
        pthread_rwlock_unlock(rwlock);
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
            pthread_rwlock_wrlock(rwlock);
            insert_state_entry(head, packet);
            pthread_rwlock_unlock(rwlock);
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
        } else {
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
        }
    }

    // ステートテーブルからパケットを検証する
    pthread_rwlock_wrlock(rwlock);
    PacketResult result = PACKET_DROP;
    bool exists_entry = false;
    StateTableEntry *match_entry = lookup_state_table(*head, packet);
    if (match_entry != NULL) {
        if (check_entry_timeout(match_entry) == true) {
            delete_entry(head, match_entry);
        } else {
            match_entry->last_activity = time(NULL);
            exists_entry = true;
            result = PACKET_ACCEPT;
        }
    }
    pthread_rwlock_unlock(rwlock);

    if (result == PACKET_DROP) {
        // ルールからパケットを検証する
        pthread_rwlock_rdlock(rwlock);
        PacketEvalInfo pkt_info = { packet, rules, rule_count, policy };
        result = judge_packet(&pkt_info);
        if (pkt_info.match_index != -1) { // パケットと一致するルールが存在した場合
            match_rule = &rules[pkt_info.match_index];
            log_flag = match_rule->log;
        }
        pthread_rwlock_unlock(rwlock);
    }

    if (log_flag == LOG_ENABLED) {
        log_packet(log_fp, packet, match_rule, policy);
    }

    switch (result) {
        case PACKET_ACCEPT:
            if (exists_entry == false) {
                pthread_rwlock_wrlock(rwlock);
                insert_state_entry(head, packet);
                pthread_rwlock_unlock(rwlock);
            }
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