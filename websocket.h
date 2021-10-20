//
// Created by juno on 2021/4/9.
//

#ifndef WEBSOCKET_WEBSOCKET_H
#define WEBSOCKET_WEBSOCKET_H
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "socket.h"
#include "websocket.h"
#include "ubus.h"
#include "hashmap.h"

#define WEBSOCKET_SHAKE_KEY_LEN 16

//发包数据量 10K
#define SEND_PKG_MAX (10240)

//收包缓冲区大小 10K+
#define RECV_PKG_MAX (SEND_PKG_MAX + 16)

typedef enum {
    WDT_NULL = 0,
    WDT_MINDATA,
    WDT_TXTDATA,
    WDT_BINDATA,
    WDT_DISCONN,
    WDT_PING,
    WDT_PONG
}websocket_data_type;

typedef enum {
    WET_NONE = 0,
    WET_EPOLL,
    WET_SEND,
    WET_LOGIN,
    WET_LOGIN_TIMEOUT,
    WET_PKG_DIS
}websocket_exit_type;

struct websocket_header {
    char path[128];
    char ver[2];
    char key[128];
};

#define MAX_CLIENT 1024

struct websocket_data_hdr {
#if __BYTE_ORDER__ ==__ORDER_BIG_ENDIAN__
    unsigned fin:1;
    unsigned rsv:3;
    unsigned opcode:4;
    unsigned mask:1;
    unsigned payload:7;
#else
    unsigned opcode:4;
    unsigned rsv:3;
    unsigned fin:1;
    unsigned payload:7;
    unsigned mask:1;
#endif
    union {
        uint8_t maskkey[4];
        uint16_t payload;
        uint8_t data[0];
    }ext16;
    union {
        uint8_t maskkey[4];
        uint32_t payload[2];
        uint8_t data[0];
    }ext64;
    uint8_t maskkey[4];
    uint8_t data[0];
}__attribute__((packed, aligned(1)));

struct websocket_message {
    websocket_data_type type;
    ssize_t len;
    uint8_t *data;
};
struct websocket_client {
    struct websocket_header *hdr;
    int fd;
    websocket_exit_type  exitType;
    bool isLogin;
    bool Online;
    uint32_t  recvBytes;
    uint32_t order;
    uint32_t loginTimeout;
    struct websocket_message *msg;
    int (*OnLogin)(struct websocket_client *);
    int (*OnMessage)(struct websocket_client *, const uint8_t *, ssize_t, websocket_data_type);
    int (*OnExit)(struct websocket_client *);
    int (*recv)(struct websocket_client *);
    int (*send)(struct websocket_client *wsc, char *data, ssize_t len, bool mask, websocket_data_type type);
    struct ubus *ubus;
};

struct websocket_server {
    int fd;
    int fd_epoll;
    int count;
    int load;
    bool running;
    char path[128];
    void *priv;
    pthread_t tid;
    int (*start_svr)(struct websocket_server *, int);
    int (*add_wsc)(struct websocket_server *wss, int fd);
    int (*detect_client)(struct websocket_server *wss);
    map_void_t *map;
};

int buildResponseShakekey(const char *inkey, ssize_t len, char *outkey);
struct websocket_server *new_weboskcet_server(const char *path);
struct websocket_client *new_client(void);
void websocket_delayus(unsigned int us);
void websocket_delayms(unsigned int ms);
int buildshakekey(char *key);
char *getrandomstring(ssize_t len);
#endif //WEBSOCKET_WEBSOCKET_H
