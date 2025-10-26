#ifndef FIREWALL_RULE_H
#define FIREWALL_RULE_H

#include <stdbool.h>
#include "firewall_config.h"

void init_rule_struct(FirewallRule *rule);
void set_default_rule_values(FirewallRule *rule);
bool is_rule_unspecified(const FirewallRule *rule);
void copy_rule(const FirewallRule *src_rule, FirewallRule *dst_rule);

#endif