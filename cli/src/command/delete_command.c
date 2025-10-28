#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_validation.h"
#include "cli_utils.h"
#include "rule_manager.h"
#include "domain_socket_utils.h"

bool delete_command(
    const char *filepath,
    ChainType target_chain,
    const char *target_line_str
)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ルールの削除を完了できませんでした。";
    FILE *rule_fp = NULL;
    FILE *tmp_fp = NULL;
    int fd = -1;
    bool ret = false;

    // 引数チェック
    if (filepath == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (target_chain == CHAIN_UNSPECIFIED) {
        err_msg = "エラー：-c オプションで削除するルールのチェインを指定してください。";
        goto cleanup;
    }
    if (target_line_str == NULL) {
        err_msg = "エラー：削除するルールの行番号を指定してください。";
        goto cleanup;
    }
    int target_line = validate_and_convert_line(target_line_str);
    if (target_line == -1) {
        err_msg = "エラー：行番号には1以上の整数を指定してください";
        goto cleanup;
    }

    // ファイルのオープンとロック
    rule_fp = fopen(filepath, "r");
    tmp_fp = fopen(TMP_RULE_FILE, "w+");
    if (rule_fp == NULL || tmp_fp == NULL) {
        goto cleanup;
    }
    fd = fileno(rule_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    if (copy_file(rule_fp, tmp_fp) == false) {
        goto cleanup;
    }

    // ルールファイルの正当性を検証
    FileValidationResult validation_result = is_valid_rule_file(tmp_fp);
    switch (validation_result) {
        case FILE_VALID:
            break;
        case FILE_NO_CONTENT:
            err_msg = "エラー：ルールが存在しません。"
                      "addコマンドで追加してください。";
            goto cleanup;
            break; // NOT REACHED
        case FILE_INVALID:
            err_msg =  "エラー：ルールファイルが不正な形式なため、"
                       "ルールを削除できません。";
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    RuleDeleteResult delete_result =
        delete_rule(tmp_fp, target_chain, target_line);
    switch (delete_result) {
        case DELETE_SUCCESS:
            break;
        case DELETE_ERR_INVALID_LINE_NUM:
            err_msg = "エラー：指定した行にルールは存在しません。";
            goto cleanup;
            break; // NOT REACHED
        case DELETE_ERR_INTERNAL:
            goto cleanup;
            break; // NOT REACHED
        default:
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
            printf("ルールが削除されました。\n");
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