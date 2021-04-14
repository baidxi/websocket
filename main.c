#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "socket.h"
#include "websocket.h"
#include "common.h"
int main() {
    struct socket_server *sock = new_socket("0.0.0.0", 8088);
    struct websocket_server *wss = new_weboskcet_server("/ws");

    pr_info("socket create ok\n");


    if (sock)
        sock->start(sock);

    if (wss) {
        sock->wss = wss;
        wss->fd = sock->fd;
        wss->start_svr(wss, 1024);
    }

    websocket_delayms(1000);


    detect_client(wss);


    return 0;
}
