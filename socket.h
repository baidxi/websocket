//
// Created by juno on 2021/4/9.
//

#ifndef WEBSOCKET_SOCKET_H
#define WEBSOCKET_SOCKET_H
#include <stdint.h>
#include <pthread.h>
#include "websocket.h"

struct socket_server {
    int fd;
    int epoll_fd;
    pthread_t tid;
    int (*start)(struct socket_server *);
    struct websocket_server *wss;
};

struct socket_server *new_socket(const char *ip, uint16_t port);

#endif //WEBSOCKET_SOCKET_H
