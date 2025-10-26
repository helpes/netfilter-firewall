#ifndef UPDATE_COMMAND_H
#define UPDATE_COMMAND_H

#include <stdbool.h>
#include "firewall_config.h"

bool update_command(
    const char *filepath,
    FirewallRule *rule_to_update,
    ChainType target_chain,
    const char *target_line_str
);

#endif