#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include "packet_handler.h"
#include "judge_packet.h"
#include "log_packet.h"

int handle_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
)
{
    PacketHandlerArgs *args = (PacketHandlerArgs *)data;
    FILE **log_fp = args->log_fp;
    FirewallRule *rules = NULL;
    size_t rule_count = 0;
    ActionType policy = DEFAULT_POLICY;
    FirewallRule *match_rule = NULL;
    LogStatus log_flag = LOG_DISABLED; // ToDo: 初期値をファイルから参照するように変更

    if (args->fw_rules != NULL) {
        rules = *(args->fw_rules);
    }
    if (args->fw_rule_count != NULL) {
        rule_count = *(args->fw_rule_count);
    }
    if (args->policy != NULL) {
        policy = *(args->policy);
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
    if (rules == NULL || rule_count == 0) {
        if (log_flag == LOG_ENABLED) {
            log_packet(log_fp, packet, match_rule, policy);
        }
        if (policy == ACTION_ACCEPT) {
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
        } else if (ACTION_DROP) {
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
        }
    }

    // パケットを検証する
    PacketEvalInfo pkt_info = { packet, packet_len, rules, rule_count, policy };
    PacketResult result = judge_packet(&pkt_info);
    if (pkt_info.match_index != -1) { // パケットと一致するルールが存在
        match_rule = &rules[pkt_info.match_index];
        log_flag = match_rule->log;
    }

    switch (result) {
        case PACKET_ACCEPT:
            if (log_flag == LOG_ENABLED) {
                log_packet(log_fp, packet, match_rule, policy);
            }
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, NULL);
            break; // NOT REACHED
        case PACKET_DROP:
            if (log_flag == LOG_ENABLED) {
                log_packet(log_fp, packet, match_rule, policy);
            }
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
        default:
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, NULL);
            break; // NOT REACHED
    }
}