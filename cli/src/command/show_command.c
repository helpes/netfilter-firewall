#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_validation.h"
#include "rule_manager.h"

bool show_command(const char *rule_file, const char *config_file)
{
    char *err_msg = "予期せぬエラーが発生したため、"
                    "ルールの表示ができませんでした。";
    FILE *rule_fp = NULL;
    FILE *config_fp = NULL;
    int rule_fd = -1;
    int config_fd = -1;
    bool ret = false;

    // 引数チェック
    if (rule_file == NULL) {
        errno = EINVAL;
        return false;
    }

    // ファイルのオープンとロック
    rule_fp = fopen(rule_file, "r");
    config_fp = fopen(config_file, "r");
    if (rule_fp == NULL || config_fp == NULL) {
        goto cleanup;
    }
    rule_fd = fileno(rule_fp);
    config_fd = fileno(config_fp);
    if (rule_fd == -1 || config_fd == -1) {
        goto cleanup;
    }
    if (flock(rule_fd, LOCK_SH) == -1 || flock(config_fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    // ルールファイルの正当性を検証
    if (is_valid_rule_file(rule_fp) == FILE_INVALID) {
        err_msg = "エラー：ルールファイルが不正な形式なため、"
                  "ルールを表示できません";
        goto cleanup;
    }

    if (show_rules(rule_fp, config_fp) == false) {
        goto cleanup;
    }

    ret = true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (rule_fd != -1) {
        flock(rule_fd, LOCK_UN);
    }
    if (config_fd != -1) {
        flock(config_fd, LOCK_UN);
    }
    if (rule_fp != NULL) {
        fclose(rule_fp);
    }
    if (config_fp != NULL) {
        fclose(config_fp);
    }
    return ret;
}