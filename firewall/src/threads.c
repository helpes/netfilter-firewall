#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "threads.h"
#include "nfq_config.h"
#include "firewall_io.h"
#include "domain_socket_utils.h"

void *nfq_handler_thread(void *arg)
{
    NfqHandlerArgs *args = (NfqHandlerArgs *)arg;
    pthread_rwlock_t *rw_lock = args->rw_lock;
    struct nfq_handle *h = args->h;
    int fd = nfq_fd(args->h);
    char buf[PACKET_BUFFER_SIZE] __attribute__ ((aligned));

    while (1) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len >= 0) {
            pthread_rwlock_rdlock(rw_lock);
            nfq_handle_packet(h, buf, len);
            pthread_rwlock_unlock(rw_lock);
        }
    }

    return NULL;
}

void *command_listener_thread(void *arg)
{
    CmdListenerArgs *args = (CmdListenerArgs *)arg;
    pthread_rwlock_t *rw_lock = args->rw_lock;
    int domain_sock = args->domain_sock;
    char *config_file = args->config_file;
    char *rule_file = args->rule_file;
    FirewallConfig *config = args->config;
    FirewallRule **input_rules = args->input_rules;
    FirewallRule **output_rules = args->output_rules;
    RuleCounts *rule_counts = args->rule_counts;

    while (1) {
        int client = accept(domain_sock, NULL, NULL);
        if (client == -1) {
            continue;
        }

        ServerCommand cmd;
        ssize_t n = recv(client, &cmd, sizeof(cmd), 0);
        if (n == -1) {
            close(client);
            continue;
        }

        ServerResponse res = RES_FAILURE;
        bool success = false;
        switch (cmd) {
            case CMD_RELOAD_RULES:
                pthread_rwlock_wrlock(rw_lock);
                success = reload_rules(
                    rule_file, input_rules, output_rules, rule_counts
                );
                pthread_rwlock_unlock(rw_lock);
                if (success == true) {
                    res = RES_SUCCESS;
                }
                break;
            case CMD_RELOAD_CONFIG:
                pthread_rwlock_wrlock(rw_lock);
                success = reload_config(
                    config_file, config
                );
                pthread_rwlock_unlock(rw_lock);
                if (success == true) {
                    res = RES_SUCCESS;
                }
                break;
            case CMD_SHUTDOWN:
                // ToDo: シャットダウン処理
                break;
            default:
                break;
        }
        send(client, &res, sizeof(res), 0);
        close(client);
    }

    return NULL;
}