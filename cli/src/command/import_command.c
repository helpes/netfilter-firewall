#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_io.h"
#include "firewall_validation.h"
#include "domain_socket_utils.h"

bool import_command(const char *dst_file, const char *src_file)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ルールのインポートを完了できませんでした。";
    FILE *dst_fp = NULL;
    FILE *src_fp = NULL;
    FILE *tmp_fp = NULL;
    int dst_fd = -1;
    bool ret = false;

    // 引数チェック
    if (dst_file == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (src_file == NULL) {
        err_msg = "エラー：インポートするファイルを指定してください。";
        goto cleanup;
    }
    if (access(src_file, F_OK) == -1) {
        if (errno == ENOENT) {
            err_msg = "エラー：指定したファイルが見つかりませんでした。";
        }
        goto cleanup;
    }

    // ファイルのオープンとロック
    dst_fp = fopen(dst_file, "r");
    src_fp = fopen(src_file, "r");
    tmp_fp = fopen(TMP_RULE_FILE, "w");
    if (dst_fp == NULL || src_fp == NULL || tmp_fp == NULL) {
        goto cleanup;
    }
    dst_fd = fileno(dst_fp);
    if (dst_fd == -1) {
        goto cleanup;
    }
    if (flock(dst_fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    // ルールファイルの正当性を検証
    if (is_valid_rule_file(src_fp) == FILE_INVALID) {
        err_msg = "指定したファイルは不正な形式のため、"
                  "ルールをインポートできません。";
        goto cleanup;
    }

    if (copy_file(src_fp, tmp_fp) == false) {
        goto cleanup;
    }
    fclose(tmp_fp);
    tmp_fp = NULL;
    if (rename(TMP_RULE_FILE, dst_file) == -1) {
        goto cleanup;
    }
    flock(dst_fd, LOCK_UN);
    fclose(dst_fp);
    dst_fd = -1;
    dst_fp = NULL;

    // ファイアウォール本体にルールの更新を伝える
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_RULES
    );
    switch (response) {
        case RES_SUCCESS:
            printf("指定したファイルのルールが適用されました。\n");
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
    if (dst_fd != -1) {
        flock(dst_fd, LOCK_UN);
    }
    if (dst_fp != NULL) {
        fclose(dst_fp);
    }
    if (src_fp != NULL) {
        fclose(src_fp);
    }
    if (tmp_fp != NULL) {
        fclose(tmp_fp);
    }
    if (access(TMP_RULE_FILE, F_OK) == 0) {
        unlink(TMP_RULE_FILE);
    }
    return ret;
}