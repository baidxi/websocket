//
// Created by juno on 2021/4/9.
//
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include "socket.h"
#include "common.h"
#include "websocket.h"

static void socket_server(void *args)
{
    struct socket_server *svr = args;
    struct epoll_event ev;
    struct epoll_event events[MAX_CLIENT];
    struct sockaddr_in client_addr;
    int n;
    svr->epoll_fd = epoll_create(1024);
    _epoll_ctrl(svr->epoll_fd, svr->fd, EPOLLIN, EPOLL_CTL_ADD, NULL);

    while(1) {
        n = epoll_wait(svr->epoll_fd, events, MAX_CLIENT, 500);
        if (n >= 0) {
            for (int i = 0; i < n; i++)
            {
                if (events[i].data.fd == svr->fd) {
                    int newfd = accept(svr->fd, &client_addr, &n);
                    if (newfd >= 0) {
                        websocket_add_client(svr->wss, newfd);
                    }
                }
            }
        }
    }
}

static int start_svr(struct socket_server *server)
{
    pr_info("start\n");
    if (listen(server->fd, 0) < 0) {
        pr_err("listen socket failed:%s\n", strerror(errno));
        close(server->fd);
        free(server);
        return -1;
    }
    return new_thread(server, &socket_server);
}

struct socket_server *new_socket(const char *ip, uint16_t port)
{
    int fd;
    int ret;
    struct sockaddr_in addr;
    struct socket_server *server;
    socklen_t  len;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    len = sizeof(addr);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        pr_err("create socket failed:%s\n", strerror(errno));
        return NULL;
    }

    ret = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, ret | O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ret, sizeof(ret));

    if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
        pr_err("bind socket failed:%s\n", strerror(errno));
        return NULL;
    }

    server = malloc(sizeof(struct socket_server));
    server->fd = fd;
    server->start = &start_svr;
    return server;
}
