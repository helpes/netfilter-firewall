#ifndef DOMAIN_SOCKET_UTILS_H
#define DOMAIN_SOCKET_UTILS_H

#include <stdbool.h>

#define SERVER_TIMEOUT_SEC 5

typedef enum {
    CMD_RELOAD_RULES,  // ルールを再読み込みするコマンド
    CMD_RELOAD_CONFIG, // 設定を再読み込みするコマンド
    CMD_SHUTDOWN       // ファイアウォールを終了するコマンド
} ServerCommand;

typedef enum {
    RES_SUCCESS, // コマンドが成功
    RES_FAILURE, // コマンドが失敗
    RES_TIMEOUT, // サーバがタイムアウト
    RES_ERROR    // エラーが発生
} ServerResponse;

int create_server_domain_socket(const char *filepath, int backlog);
ServerResponse send_command_to_server(
    const char *filepath,
    ServerCommand command
);

#endif