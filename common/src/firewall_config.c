#include <stddef.h>
#include <stdbool.h>
#include "firewall_config.h"

// ルールのデフォルト値
const ActionType DEFAULT_POLICY = ACTION_DROP;
const ProtocolType DEFAULT_PROTOCOL = PROTO_ANY;
const char *DEFAULT_IP_ADDR = "ANY";
const int DEFAULT_PORT = -1;
const ActionType DEFAULT_ACTION = ACTION_DROP;
const LogStatus DEFAULT_LOG_STATUS = LOG_DISABLED;
const RuleState DEFAULT_RULE_STATE = RULE_ENABLED;

// 設定ファイルの項目値
static const char *policy_values[] = {"ACCEPT", "DROP", NULL};
static const char *empty_values[] = {NULL};

const ConfigItems config_items[] = {
    {"INPUT_POLICY", policy_values},
    {"OUTPUT_POLICY", policy_values},
    {NULL, empty_values}
};