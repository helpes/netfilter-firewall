#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include "firewall_config.h"
#include "domain_socket_utils.h"
#include "command/shutdown_command.h"

bool shutdown_command(void)
{
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_SHUTDOWN
    );
    switch (response) {
        case RES_SUCCESS:
            time_t start_time = time(NULL);
            // ファイアウォールが終了するまでループで待機
            // DOMAIN_SOCKET_PATHが存在している間は起動していると見なす
            while (access(DOMAIN_SOCKET_PATH, F_OK) == 0) {
                if (time(NULL) - start_time > SHUTDOWN_TIMEOUT_SEC) {
                    fprintf(stderr, "エラー：ファイアウォールが完全に終了する前に"
                                    "タイムアウトしました。\n");
                    return false;
                }

                usleep(100000);
            }
            printf("ファイアウォールが終了しました。\n");
            break;
        case RES_FAILURE:
            fprintf(stderr, "エラー：予期せぬエラーが発生しました。\n");
            return false;
            break; // NOT REACHED
        case RES_TIMEOUT:
            fprintf(stderr, "エラー：ファイアウォールからの応答がタイムアウトしました。\n");
            return false;
            break; // NOT REACHED
        case RES_ERROR:
            fprintf(stderr, "エラー：ファイアウォールへの接続に失敗しました。\n");
            return false;
            break; // NOT REACHED
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}