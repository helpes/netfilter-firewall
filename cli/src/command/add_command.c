#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_rule.h"
#include "firewall_validation.h"
#include "rule_manager.h"
#include "domain_socket_utils.h"

bool add_command(const char *filepath, FirewallRule *rule_to_add)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ルールの追加を完了できませんでした。";
    FILE *rule_fp = NULL;
    FILE *tmp_fp = NULL;
    int fd = -1;
    bool ret = false;

    // 引数チェック
    if (filepath == NULL || rule_to_add == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (rule_to_add->chain == CHAIN_UNSPECIFIED) {
        err_msg = "エラー：-c オプションでチェインを指定してください。";
        goto cleanup;
    }
    if (rule_to_add->action == ACTION_UNSPECIFIED) {
        err_msg = "エラー：-a オプションでパケットに対するアクションを指定してください。";
        goto cleanup;
    }
    if (rule_to_add->protocol == PROTO_ICMP &&
        (rule_to_add->src_port != PORT_UNSPECIFIED ||
         rule_to_add->dst_port != PORT_UNSPECIFIED)) {
        err_msg = "エラー：ICMPにポート番号は設定できません。";
        goto cleanup;
    }

    // ファイルのオープンとロック
    rule_fp = fopen(filepath, "r");
    if (rule_fp == NULL) {
        goto cleanup;
    }
    fd = fileno(rule_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }
    tmp_fp = fopen(TMP_RULE_FILE, "w+");
    if (tmp_fp == NULL) {
        goto cleanup;
    }

    if (copy_file(rule_fp, tmp_fp) == false) {
        goto cleanup;
    }

    // デフォルトの値を設定
    set_default_rule_values(rule_to_add);

    // ルールファイルの正当性を検証
    if (is_valid_rule_file(tmp_fp) == FILE_INVALID) {
        err_msg = "エラー：ルールファイルが不正な形式なため、"
                  "ルールを追加できません。";
        goto cleanup;
    }

    // 追加したいルールと同じルールが既に存在するか確認する
    char *success_msg = NULL;
    MatchLines match_lines;
    RuleExistsResult exists_result =
        rule_exists_in_file(tmp_fp, rule_to_add, &match_lines);
    switch (exists_result) {
        case RULE_MATCH:
            err_msg = "エラー：既に同じルールが存在します。";
            goto cleanup;
            break; // NOT REACHED
        case RULE_CONFLICT:
            int target_index = (rule_to_add->chain == CHAIN_INPUT)
                ? match_lines.input_line
                : match_lines.output_line;
            if (update_rule(tmp_fp, rule_to_add, rule_to_add->chain,
                            target_index) != UPDATE_SUCCESS) {
                goto cleanup;
            }
            success_msg = "基本情報が同じルールが存在したので更新しました。";
            break;
        case RULE_NOT_FOUND:
            if (add_rule(tmp_fp, rule_to_add) == false) {
                goto cleanup;
            }
            success_msg = "ルールは正常に追加されました。";
            break;
        case RULE_ERROR:
            goto cleanup;
            break; // NOT REACHED
    }

    fclose(tmp_fp);
    tmp_fp = NULL;
    if (rename(TMP_RULE_FILE, filepath) == -1) {
        goto cleanup;
    }
    flock(fd, LOCK_UN);
    fclose(rule_fp);
    fd = -1;
    rule_fp = NULL;

    // ファイアウォール本体にルールの更新を伝える
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_RULES
    );
    switch (response) {
        case RES_SUCCESS:
            printf("%s\n", success_msg);
            break;
        case RES_FAILURE:
            err_msg = "エラー：ファイアウォールがルールの再読み込みに失敗しました。";
            goto cleanup;
            break; // NOT REACHED
        case RES_TIMEOUT:
            err_msg = "エラー：ファイアウォールからの応答がタイムアウトしました。";
            goto cleanup;
            break; // NOT REACHED
        case RES_ERROR:
            err_msg = "エラー：ファイアウォールへの接続に失敗しました。";
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    ret = true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    if (rule_fp != NULL) {
        fclose(rule_fp);
    }
    if (tmp_fp != NULL) {
        fclose(tmp_fp);
    }
    if (access(TMP_RULE_FILE, F_OK) == 0) {
        unlink(TMP_RULE_FILE);
    }
    return ret;
}