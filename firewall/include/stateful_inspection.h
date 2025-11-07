#ifndef STATEFUL_INSPECTION_H
#define STATEFUL_INSPECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

typedef struct StateTableEntry {
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    void *proto_info;
    time_t last_activity;
    struct StateTableEntry *next;
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
bool insert_state_entry(
    StateTableEntry **head,
    const unsigned char *packet,
    pthread_rwlock_t *rwlock
);
void destroy_state_table(StateTableEntry **head);
StateTableEntry *lookup_state_table(
    StateTableEntry *head,
    const unsigned char *packet,
    pthread_rwlock_t *rwlock
);

#endif