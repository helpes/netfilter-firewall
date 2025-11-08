#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include "stateful_inspection.h"
#include "firewall_config.h"

bool init_state_entry(StateTableEntry **entry_out, const unsigned char *packet)
{
    StateTableEntry *entry = NULL;
    TcpState *tcp_info = NULL;
    UdpState *udp_info = NULL;
    bool ret = false;

    if (entry_out == NULL || packet == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    entry = malloc(sizeof(StateTableEntry));
    if (entry == NULL) {
        goto cleanup;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    entry->protocol = ip_hdr->protocol;
    entry->src_ip = ip_hdr->saddr;
    entry->dst_ip = ip_hdr->daddr;
    entry->last_activity = time(NULL);
    entry->next = NULL;

    switch (entry->protocol) {
        case IPPROTO_ICMP:
            entry->proto_info = NULL;
            break;
        case IPPROTO_TCP:
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_hdr_len);
            tcp_info = malloc(sizeof(TcpState));
            if (tcp_info == NULL) {
                goto cleanup;
            }
            tcp_info->src_port = tcp_hdr->th_sport;
            tcp_info->dst_port = tcp_hdr->th_dport;
            entry->proto_info = tcp_info;
            break;
        case IPPROTO_UDP:
            struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_hdr_len);
            udp_info = malloc(sizeof(UdpState));
            if (udp_info == NULL) {
                goto cleanup;
            }
            udp_info->src_port = udp_hdr->uh_sport;
            udp_info->dst_port = udp_hdr->uh_dport;
            entry->proto_info = udp_info;
            break;
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    ret = true;

    cleanup:
    if (ret == true) {
        *entry_out = entry;
    } else {
        free(tcp_info);
        free(udp_info);
        free(entry);
        *entry_out = NULL;
    }
    return ret;
}

bool insert_state_entry(
    StateTableEntry **head,
    const unsigned char *packet,
    pthread_rwlock_t *rwlock
)
{
    if (head == NULL || packet == NULL) {
        errno = EINVAL;
        return false;
    }

    if (*head != NULL) {
        // 同じエントリーがあれば、最終アクティブ時間を更新して終了
        StateTableEntry *existing_entry = lookup_state_table(*head, packet, rwlock);
        if (existing_entry != NULL) {
            existing_entry->last_activity = time(NULL);
            return true;
        }
    }

    StateTableEntry *new_entry = NULL;
    if (init_state_entry(&new_entry, packet) == false) {
        return false;
    }

    pthread_rwlock_wrlock(rwlock);
    new_entry->next = *head;
    *head = new_entry;
    pthread_rwlock_unlock(rwlock);

    return true;
}

void destroy_state_table(StateTableEntry **head)
{
    if (head == NULL || *head == NULL) {
        return;
    }

    StateTableEntry *current_entry = *head;
    while (current_entry != NULL) {
        StateTableEntry *tmp_entry = current_entry->next;
        free(current_entry->proto_info);
        free(current_entry);
        current_entry = tmp_entry;
    }
    *head = NULL;
}

StateTableEntry *lookup_state_table(
    StateTableEntry *head,
    const unsigned char *packet,
    pthread_rwlock_t *rwlock
)
{
    if (head == NULL || packet == NULL) {
        errno = EINVAL;
        return NULL;
    }

    StateTableEntry *target_entry = NULL;
    if (init_state_entry(&target_entry, packet) == false) {
        return NULL;
    }


    pthread_rwlock_rdlock(rwlock);
    StateTableEntry *current_entry = head;
    while (current_entry != NULL) {
        if (target_entry->protocol != current_entry->protocol) {
            current_entry = current_entry->next;
            continue;
        }

        // IPアドレスの順方向/逆方向のいずれかが一致するか確認
        bool ip_match_fwd = (
            target_entry->src_ip == current_entry->src_ip &&
            target_entry->dst_ip == current_entry->dst_ip
        );
        bool ip_match_rev = (
            target_entry->src_ip == current_entry->dst_ip &&
            target_entry->dst_ip == current_entry->src_ip
        );
        if (ip_match_fwd == false && ip_match_rev == false) {
            current_entry = current_entry->next;
            continue;
        }

        switch (target_entry->protocol) {
            case IPPROTO_ICMP:
                break;
            case IPPROTO_TCP:
                TcpState *target_tcp = target_entry->proto_info;
                TcpState *current_tcp = current_entry->proto_info;
                bool tport_match_fwd = (
                    target_tcp->src_port == current_tcp->src_port &&
                    target_tcp->dst_port == current_tcp->dst_port
                );
                bool tport_match_rev = (
                    target_tcp->src_port == current_tcp->dst_port &&
                    target_tcp->dst_port == current_tcp->src_port
                );
                if (tport_match_fwd == false && tport_match_rev == false) {
                    current_entry = current_entry->next;
                    continue;
                }
                break;
            case IPPROTO_UDP:
                UdpState *target_udp = target_entry->proto_info;
                UdpState *current_udp = current_entry->proto_info;
                bool uport_match_fwd = (
                    target_udp->src_port == current_udp->src_port &&
                    target_udp->dst_port == current_udp->dst_port
                );
                bool uport_match_rev = (
                    target_udp->src_port == current_udp->dst_port &&
                    target_udp->dst_port == current_udp->src_port
                );
                if (uport_match_fwd == false && uport_match_rev == false) {
                    current_entry = current_entry->next;
                    continue;
                }
                break;
            default:
                break;
        }

        free(target_entry->proto_info);
        free(target_entry);
        pthread_rwlock_unlock(rwlock);
        return current_entry;
    }

    free(target_entry->proto_info);
    free(target_entry);
    pthread_rwlock_unlock(rwlock);
    return NULL;
}