#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_io.h"

bool export_command(const char *src_file, const char *dst_file)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ルールのエクスポートを完了できませんでした。";
    FILE *src_fp = NULL;
    FILE *dst_fp = NULL;
    int src_fd = -1;
    int dst_fd = -1;
    bool ret = false;

    // 引数チェック
    if (src_file == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (dst_file == NULL) {
        err_msg = "エラー：エクスポートするファイルを指定してください。";
        goto cleanup;
    }

    // ファイルのオープンとロック
    src_fp = fopen(src_file, "r");
    if (src_fp == NULL) {
        goto cleanup;
    }
    RuleCounts counts;
    if (get_rule_counts_from_file(src_fp, &counts) == false) {
        goto cleanup;
    }
    if (counts.total_count == 0) {
        err_msg = "エラー：ルールが存在しないため、"
                  "エクスポートが完了しませんでした。";
        goto cleanup;
    }
    dst_fp = fopen(dst_file, "r+");
    if (dst_fp == NULL) {
        if (errno == ENOENT) {
            // ファイルが存在しなければ作成する
            dst_fp = fopen(dst_file, "w");
            errno = 0;
        }
        if (dst_fp == NULL) {
            goto cleanup;
        }
        printf("%sを作成しました。\n", dst_file);
    }
    src_fd = fileno(src_fp);
    dst_fd = fileno(dst_fp);
    if (src_fd == -1 || dst_fd == -1) {
        goto cleanup;
    }
    if (flock(src_fd, LOCK_SH) == -1 || flock(dst_fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    if (copy_file(src_fp, dst_fp) == false) {
        goto cleanup;
    }
    printf("ルールのエクスポートが完了しました。\n");

    ret = true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (src_fd != -1) {
        flock(src_fd, LOCK_UN);
    }
    if (dst_fd != -1) {
        flock(dst_fd, LOCK_UN);
    }
    if (src_fp != NULL) {
        fclose(src_fp);
    }
    if (dst_fp != NULL) {
        fclose(dst_fp);
    }
    return ret;
}