#ifndef CHANGE_POLICY_COMMAND_H
#define CHANGE_POLICY_COMMAND_H

#include "firewall_config.h"

bool change_policy_command(
    const char *filepath,
    ActionType policy_to_change,
    ChainType target_chain
);

#endif