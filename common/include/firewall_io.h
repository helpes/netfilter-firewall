#ifndef FIREWALL_IO_H
#define FIREWALL_IO_H

#include <stdbool.h>
#include "firewall_config.h"

typedef enum {
    RULE_MATCH,     // 同じルールが存在する
    RULE_CONFLICT,  // 基本情報だけが同じルールが存在する
    RULE_NOT_FOUND, // 同じルールは存在しない
    RULE_ERROR      // エラーが発生
} RuleExistsResult;

typedef enum {
    POLICY_CHANGE_SUCCESS,       // ポリシーの変更に成功
    POLICY_CHANGE_ERR_NO_CHANGE, // 元のポリシーから変更されていない
    POLICY_CHANGE_ERR_INTERNAL   // 内部エラーが発生
} PolicyChangeResult;

typedef struct {
    int file_line;
    int input_line;
    int output_line;
} MatchLines;

bool load_config_from_file(FILE *fp, FirewallConfig *config_out);
bool reload_config(const char *filepath, FirewallConfig *config_out);
bool load_rules_from_file(
    FILE *fp,
    FirewallRule **rules_out,
    RuleCounts *rule_counts_out
);
bool load_rules_by_chain(
    FILE *fp,
    FirewallRule **input_rules_out,
    FirewallRule **output_rules_out,
    RuleCounts *rule_counts_out
);
bool reload_rules(
    const char *filepath,
    FirewallRule **input_rules_out,
    FirewallRule **output_rules_out,
    RuleCounts *rule_counts_out
);
bool save_rules_to_file(
    FILE *fp,
    const FirewallRule *rules_to_save,
    size_t rule_len
);
RuleExistsResult rule_exists_in_file(
    FILE *fp,
    const FirewallRule *target_rule,
    MatchLines *match_lines_out
);
PolicyChangeResult change_policy(
    FILE *fp,
    ChainType target_chain,
    ActionType policy_to_change
);
bool get_rule_counts_from_file(FILE *fp, RuleCounts *counts_out);
bool copy_file(FILE *src_fp, FILE *dst_fp);

#endif