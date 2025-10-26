#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "firewall_config.h"

void init_rule_struct(FirewallRule *rule)
{
    if (rule == NULL) {
        errno = EINVAL;
        return;
    }

    snprintf(rule->src_ip, sizeof(rule->src_ip), "%s", IP_ADDR_UNSPECIFIED);
    snprintf(rule->dst_ip, sizeof(rule->dst_ip), "%s", IP_ADDR_UNSPECIFIED);
    snprintf(rule->original, sizeof(rule->original), "%s", ORIGINAL_UNSPECIFIED);
    rule->chain = CHAIN_UNSPECIFIED;
    rule->protocol = PROTO_UNSPECIFIED;
    rule->src_port = PORT_UNSPECIFIED;
    rule->dst_port = PORT_UNSPECIFIED;
    rule->action = ACTION_UNSPECIFIED;
    rule->log = LOG_UNSPECIFIED;
    rule->state = RULE_UNSPECIFIED;
}

void set_default_rule_values(FirewallRule *rule)
{
    if (rule == NULL) {
        errno = EINVAL;
        return;
    }

    if (rule->protocol == PROTO_UNSPECIFIED) {
        rule->protocol = DEFAULT_PROTOCOL;
    }
    if (strcmp(rule->src_ip, IP_ADDR_UNSPECIFIED) == 0) {
        snprintf(rule->src_ip, sizeof(rule->src_ip), "%s", DEFAULT_IP_ADDR);
    }
    if (strcmp(rule->dst_ip, IP_ADDR_UNSPECIFIED) == 0) {
        snprintf(rule->dst_ip, sizeof(rule->dst_ip), "%s", DEFAULT_IP_ADDR);
    }
    if (rule->src_port == PORT_UNSPECIFIED) {
        rule->src_port = DEFAULT_PORT;
    }
    if (rule->dst_port == PORT_UNSPECIFIED) {
        rule->dst_port = DEFAULT_PORT;
    }
    if (rule->action == ACTION_UNSPECIFIED) {
        rule->action = DEFAULT_ACTION;
    }
    if (rule->log == LOG_UNSPECIFIED) {
        rule->log = DEFAULT_LOG_STATUS;
    }
    if (rule->state == RULE_UNSPECIFIED) {
        rule->state = DEFAULT_RULE_STATE;
    }
}


bool is_rule_unspecified(const FirewallRule *rule)
{
    if ((strcmp(rule->src_ip, IP_ADDR_UNSPECIFIED) == 0) &&
        (strcmp(rule->dst_ip, IP_ADDR_UNSPECIFIED) == 0) &&
        (strcmp(rule->original, ORIGINAL_UNSPECIFIED) == 0) &&
        rule->chain == CHAIN_UNSPECIFIED &&
        rule->protocol == PROTO_UNSPECIFIED &&
        rule->src_port == PORT_UNSPECIFIED &&
        rule->dst_port == PORT_UNSPECIFIED &&
        rule->action == ACTION_UNSPECIFIED &&
        rule->log == LOG_UNSPECIFIED &&
        rule->state == RULE_UNSPECIFIED) {
            return true;
        }

    return false;
}

void copy_rule(const FirewallRule *src_rule, FirewallRule *dst_rule)
{
    if (src_rule == NULL || dst_rule == NULL) {
        return;
    }

    dst_rule->chain = src_rule->chain;
    dst_rule->protocol = src_rule->protocol;
    dst_rule->src_port = src_rule->src_port;
    dst_rule->dst_port = src_rule->dst_port;
    dst_rule->action = src_rule->action;
    dst_rule->log = src_rule->log;
    dst_rule->state = src_rule->state;
    snprintf(dst_rule->src_ip, sizeof(dst_rule->src_ip), "%s", src_rule->src_ip);
    snprintf(dst_rule->dst_ip, sizeof(dst_rule->dst_ip), "%s", src_rule->dst_ip);
    snprintf(dst_rule->original, sizeof(dst_rule->original), "%s",
             src_rule->original);
}