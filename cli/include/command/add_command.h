#ifndef ADD_COMMAND_H
#define ADD_COMMAND_H

#include <stdbool.h>
#include "firewall_config.h"

bool add_command(const char *filepath, FirewallRule *rule_to_add);

#endif