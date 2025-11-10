#ifndef STATEFUL_INSPECTION_H
#define STATEFUL_INSPECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define TCP_CONNECTION_TIMEOUT_SEC 300
#define UDP_CONNECTION_TIMEOUT_SEC 60
#define ICMP_CONNECTION_TIMEOUT_SEC 10
#define STATE_TABLE_CLEANER_INTERVAL_SEC 30

typedef struct StateTableEntry {
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    void *proto_info;
    time_t last_activity;
    struct StateTableEntry *next;
    struct StateTableEntry *prev;
} StateTableEntry;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} TcpState;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} UdpState;

bool init_state_entry(StateTableEntry **entry_out, const unsigned char *packet);
bool insert_state_entry(StateTableEntry **head, const unsigned char *packet);
void delete_entry(StateTableEntry **head, StateTableEntry *entry_to_delete);
bool check_entry_timeout(StateTableEntry *entry_to_check);
StateTableEntry *lookup_state_table(StateTableEntry *head, const unsigned char *packet);
void cleanup_expired_entries(StateTableEntry **head);
void destroy_state_table(StateTableEntry **head);

#endif