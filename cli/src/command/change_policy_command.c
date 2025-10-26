#include <stdio.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_validation.h"
#include "domain_socket_utils.h"

bool change_policy_command(
    const char *filepath,
    ChainType target_chain,
    ActionType policy_to_change
)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ポリシーを変更できませんでした。";
    FILE *config_fp = NULL;
    int fd = -1;
    bool ret = false;

    // 引数チェック
    if (filepath == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (target_chain == CHAIN_UNSPECIFIED) {
        err_msg = "エラー：-c オプションでチェインを指定してください。";
        goto cleanup;
    }
    if (policy_to_change == ACTION_UNSPECIFIED) {
        err_msg = "エラー：-a オプションで変更するポリシーの値を指定してください。";
        goto cleanup;
    }

    // ファイルのオープンとロック
    config_fp = fopen(filepath, "r+");
    if (config_fp == NULL) {
        goto cleanup;
    }
    fd = fileno(config_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    // 設定ファイルの正当性を検証
    if (is_valid_config_file(config_fp) == FILE_INVALID) {
        err_msg = "エラー：設定ファイルが不正な形式のため、"
                  "ポリシーを変更できません。";
        goto cleanup;
    }

    // ポリシーの変更
    PolicyChangeResult change_result =
        change_policy(config_fp, target_chain, policy_to_change);
    switch (change_result) {
        case POLICY_CHANGE_SUCCESS:
            break;
        case POLICY_CHANGE_ERR_NO_CHANGE:
            err_msg = "エラー：元のポリシーから変更されていません。";
            goto cleanup;
            break; // NOT REACHED
        case POLICY_CHANGE_ERR_INTERNAL:
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    // ファイアウォールがファイルを閲覧できるよう、供給ロックに変更
    if (flock(fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    // ファイアウォール本体に設定の更新を伝える
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_CONFIG
    );
    switch (response) {
        case RES_SUCCESS:
            printf("ポリシーが更新されました。\n");
            break;
        case RES_FAILURE:
            err_msg = "エラー：ファイアウォールが設定の再読み込みに失敗しました。";
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
    if (config_fp != NULL) {
        fclose(config_fp);
    }
    return ret;
}