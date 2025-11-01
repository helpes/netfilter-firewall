#include <stddef.h>
#include <stdbool.h>
#include "firewall_config.h"

// ルールのデフォルト値
const ActionType DEFAULT_POLICY = ACTION_DROP;
const LogStatus DEFAULT_LOGGING = LOG_DISABLED;
const ProtocolType DEFAULT_PROTOCOL = PROTO_ANY;
const char *DEFAULT_IP_ADDR = "ANY";
const int DEFAULT_PORT = -1;
const ActionType DEFAULT_ACTION = ACTION_DROP;
const LogStatus DEFAULT_LOG_STATUS = LOG_DISABLED;
const RuleState DEFAULT_RULE_STATE = RULE_ENABLED;