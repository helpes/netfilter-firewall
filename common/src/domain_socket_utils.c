#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include "domain_socket_utils.h"

int create_server_domain_socket(const char *filepath, int backlog)
{
    if (filepath == NULL) {
        errno = EINVAL;
        return -1;
    }

    unlink(filepath);

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", filepath);

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(sock_fd);
        return -1;
    }

    if (listen(sock_fd, backlog) == -1) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

ServerResponse send_command_to_server(
    const char *filepath,
    ServerCommand command
)
{
    int client_sock = -1;
    ServerResponse ret = RES_ERROR;

    if (filepath == NULL) {
        goto cleanup;
    }

    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sock == -1) {
        goto cleanup;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", filepath);
    if (connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        goto cleanup;
    }
    if (send(client_sock, &command, sizeof(command), 0) == -1) {
        goto cleanup;
    }

    struct timeval timeout;
    timeout.tv_sec = SERVER_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == -1) {
        goto cleanup;
    }

    ServerResponse response;
    ssize_t n = recv(client_sock, &response, sizeof(response), 0);
    if (n == -1) {
        if (errno == EAGAIN) {
            ret = RES_TIMEOUT;
        }
        goto cleanup;
    }

    ret = response;

    cleanup:
    if (client_sock != -1) {
        close(client_sock);
    }
    return ret;
}