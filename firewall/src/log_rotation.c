#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include "firewall_config.h"

bool log_rotation(FILE **log_fp, int rotate, int rotation_size_mb)
{
    unsigned int rotation_size_bytes = rotation_size_mb * 1024 * 1024;
    struct stat st;
    if (stat(LOG_FILE, &st) == -1) {
        return false;
    }
    if (st.st_size < rotation_size_bytes) {
        // ファイルサイズが既定値未満なら何もせずに終了
        return true;
    }

    char logfile[LOG_FILE_MAX_LEN];
    snprintf(logfile, sizeof(logfile), "%s.", basename(LOG_FILE));
    DIR *dir = opendir(LOG_DIR);
    if (dir == NULL) {
        return false;
    }
    int logfile_count = 0;
    struct dirent *dp;
    while ((dp = readdir(dir)) != NULL) {
        if (strncmp(dp->d_name, logfile, strlen(logfile)) == 0) {
            logfile_count++;
        }
    }
    closedir(dir);

    // ログファイルのファイル名を一つずつずらす
    char src_filepath[LOG_FILE_MAX_LEN];
    char dst_filepath[LOG_FILE_MAX_LEN];
    for (int i = logfile_count; i >= 0; i--) {
        snprintf(src_filepath, sizeof(src_filepath), "%s.%d", LOG_FILE, i);
        snprintf(dst_filepath, sizeof(dst_filepath), "%s.%d", LOG_FILE, i + 1);

        if (i == rotate) {
            unlink(src_filepath);
        } else if (i == 0) {
            if (rename(LOG_FILE, dst_filepath) == -1) {
                return false;
            }
        } else {
            if (rename(src_filepath, dst_filepath) == -1) {
                return false;
            }
        }
    }

    // ファイルを開きなおす
    FILE *new_fp = freopen(LOG_FILE, "a", *log_fp);
    if (new_fp == NULL) {
        *log_fp = NULL;
        return false;
    }
    *log_fp = new_fp;

    return true;
}