//
// Created by juno on 2021/4/9.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <json.h>
#include "http_parser.h"
#include "base64.h"
#include "common.h"
#include "package.h"
#include "ubus.h"
#include "backend.h"
#include "hexdump.h"
#include "hashmap.h"


void websocket_delayus(unsigned int us)
{
    struct timeval tim;
    tim.tv_sec = us / 1000000;
    tim.tv_usec = us % 1000000;
    select(0, NULL, NULL, NULL, &tim);
}
void websocket_delayms(unsigned int ms)
{
    websocket_delayus(ms * 1000);
}

char *getrandomstring(ssize_t len)
{
    char *str;
    int i;
    uint8_t temp;
    srand((int32_t)time(0));
    str = malloc(len);
    for (i = 0; i < len; i++)
    {
        do {
            temp = (uint8_t)(rand() % 256);
        }while(temp != 0);

        str[i] = temp;
    }

    return str;
}

int buildshakekey(char *key)
{
    int ret;
    char *rnd = getrandomstring(WEBSOCKET_SHAKE_KEY_LEN);
    ret = base64_encode(rnd, strlen(rnd), false, key);
    free(rnd);
    return ret;
}

int buildResponseShakekey(const char *inkey, ssize_t len, char *outkey)
{
    char *clientkey;
    char *sha1data;
    int i, n;
    const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    int guidLen;

    if (inkey == NULL)
        return 0;

    guidLen = sizeof(guid);

    clientkey = calloc(len + guidLen + 10, sizeof(char));
    memcpy(clientkey, inkey, len);
    memcpy(&clientkey[len], guid, guidLen);
    clientkey[len + guidLen] = '\0';
    sha1data = SHA1(clientkey, strlen(clientkey), NULL);
    n = base64_encode(sha1data, strlen(sha1data), false, outkey);
    free(clientkey);
    return n;

}

static int remove_client(struct websocket_client *wsc)
{
    wsc->exitType = WET_PKG_DIS;
    return 0;
}

static void websocket_service_thread(void *args)
{
    struct websocket_server *wss = args;

    while(!wss->count) {
        websocket_delayms(100);
    }
    
    int nfds, i;
    struct epoll_event events[MAX_CLIENT];
    wss->running = true;

    while(wss->running) {
        nfds = epoll_wait(wss->fd_epoll, events, MAX_CLIENT, 500);
        if (nfds >= 0) {
            for (i = 0; i < nfds; i++) {
                struct websocket_client *wsc = events[i].data.ptr;
                wsc->recv(wsc);
            }
        }
    }
}


static int response_client(struct websocket_client *wsc, const char *key)
{
    char respondpkg[1024] = {0};

    build_http_respond(key, strlen(key), respondpkg);

    return send(wsc->fd, respondpkg, strlen(respondpkg), 0);
}

static int websocket_client_add_to_hashmap(struct websocket_server *wss, struct websocket_client *wsc)
{
    map_set(wss->map, wsc->hdr->key, wsc);
    wss->count += 1;
    _epoll_ctrl(wss->fd_epoll, wsc->fd, EPOLLET | EPOLLIN, EPOLL_CTL_ADD, wsc);
    return 0;

}

static int websocket_waitdata(int fd)
{
    fd_set fds;
    struct timeval tim;
    int ret;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tim.tv_sec = 3;
    tim.tv_usec = 0;

    ret = select(fd + 1, &fds, NULL, NULL, &tim);

    return ret;

}

static int isValid_request(struct websocket_server *wss, struct http_hdr *hdr)
{
    pr_debug("connection = %s upgrade = %s version = %s path = %s\n", hdr->connection, hdr->upgrade, hdr->wsc->ver, hdr->wsc->path);

    if (!strstr(hdr->connection, "Upgrade"))
        return -1;

    if (strcmp(hdr->upgrade, "websocket"))
        return -1;

    if (atoi(hdr->wsc->ver) < 13){
        return -1;
    }

    if (strcmp(wss->path, hdr->wsc->path)){
        pr_debug("path invalid: wss path = %s wsc path = %s\n", wss->path, hdr->wsc->path);
        return -1;
    }

    return 0;
}

int websocket_add_client(struct websocket_server *wss, int fd)
{
    char buf[1024] = {0};
    struct http_hdr *http;
    int n = 0;

    pr_debug("have new client connect\n");
    if (websocket_waitdata(fd) == 0) {
        pr_err("timeout\n");
        close(fd);
        return -1;
    }

    n = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL);

    http = http_parse_request(NULL, buf, n);

    if (isValid_request(wss, http) < 0) {
        pr_debug("invalid request\n");
        free(http->wsc);
        free(http);
        close(fd);
        return -1;
    }


    struct websocket_client *wsc =new_client();
    wsc->hdr = http->wsc;
    wsc->fd = fd;

    if (response_client(wsc, http->wsc->key) < 0)
    {
        pr_err("response failed:%s\n", strerror(errno));
        free(http->wsc);
        free(http);
        free(wsc);
        close(fd);
        return -1;
    }
    wsc->isLogin = true;
    wsc->Online = true;
    wsc->exitType = WET_NONE;
    if (wsc->OnLogin)
        wsc->OnLogin(wsc);

    websocket_client_add_to_hashmap(wss, wsc);

    return 0;
}


static int websocket_start(struct websocket_server *wss, int load)
{
    if (!wss)
        return -1;
    wss->load = load;
    wss->tid = new_thread(wss, &websocket_service_thread);

    if (wss->tid == -1)
        return -1;

    return 0;
}

struct websocket_server *new_weboskcet_server(const char *path)
{
    pr_debug("create new websocket server\n");
    struct websocket_server *wss = malloc(sizeof(struct websocket_server));
    if (!wss) {
        pr_err("malloc wss failed:%s\n", strerror(errno));
        return NULL;
    }

    if (!path) {
        pr_err("path empty\n");
        free(wss);
        return NULL;
    }

    strcpy(wss->path, path);
    wss->start_svr = &websocket_start;
    wss->fd_epoll = epoll_create(MAX_CLIENT);
    wss->map = malloc(sizeof(map_void_t));
    map_init(wss->map);
    pr_debug("create new websocket server path = %s\n", wss->path);
    return wss;
}

static int websocket_client_recv(struct websocket_client *wsc)
{
    char tmp[16];
    char buf[RECV_PKG_MAX] = {0};
    int n = 0;
    int ret;
    uint32_t timeout = 0;
    ssize_t  retlen;

    pr_debug("recv msg\n");
    n = recv(wsc->fd, buf, RECV_PKG_MAX, MSG_NOSIGNAL);

#ifdef DEBUG
    if (n > 0)
        hexdump(buf, n);
#endif
    if (n > 0) {
        char msg[RECV_PKG_MAX] = {0};
        wsc->msg = NULL;
        retlen = websocket_unpackage(wsc, buf, n);

        if (retlen == 0 || (retlen < 0 && n - retlen > sizeof(buf)))
        {
            if (retlen == 0) {
                pr_debug("rec empty msg\n");
            }
            retlen += recv(wsc->fd, &buf[retlen], sizeof(buf) - retlen, MSG_NOSIGNAL);
            if (retlen < 0) {
                pr_war("recv package to big\n");
                while(recv(wsc->fd, tmp, sizeof(tmp), MSG_NOSIGNAL) > 0)
                    ;
            }
            ret = -retlen;
        } else {
            if (retlen < 0) {
                ret = recv(wsc->fd, &buf[n], -retlen, MSG_NOSIGNAL);
                if (ret > 0)
                {
                    n += ret;
                    retlen += ret;
                }

                for (timeout = 0; timeout < 200 && retlen < 0;)
                {
                    websocket_delayms(5);
                    timeout += 5;
                    ret = recv(wsc->fd, &buf[n], -retlen, MSG_NOSIGNAL);
                    if (ret > 0)
                    {
                        timeout = 0;
                        n += ret;
                        retlen += ret;
                    }
                }

                retlen = websocket_unpackage(wsc, buf, n);
            }
            if (retlen > 0) {
                switch (wsc->msg->type) {
                    case WDT_PING:
                        break;
                    case WDT_PONG:
                        break;
                    case WDT_DISCONN:
                        pr_debug("remove client\n");
                        remove_client(wsc);
                        return 0;
                    default:
                        ret = retlen;
                }
            } else
                ret = -retlen;
        }
    }

    if (n <= 0)
        return 0;

    if (wsc->msg) {
        if (wsc->msg->type == WDT_DISCONN) {
            pr_debug("remove client\n");
            remove_client(wsc);
            return 0;
        } else if (wsc->msg->type > WDT_PONG) {
            remove_client(wsc);
            return 0;
        }
    }else {
        return 0;
    }

    if (ret > 0) {
        wsc->recvBytes += ret > 0 ? ret : (-ret);
    }


    if (wsc->OnMessage)
        wsc->OnMessage(wsc, wsc->msg->data, wsc->msg->len, wsc->msg->type);

    return ret;
}

int websocket_client_send(struct websocket_client *wsc, char *data, ssize_t len, bool mask, websocket_data_type type)
{
    uint8_t *pkg = NULL;
    int retlen, ret;
    int i;

    if (len < 0)
        return 0;

    if (type == WDT_NULL)
        return send(wsc->fd, data, len, MSG_NOSIGNAL);

    pkg = (uint8_t *) calloc(len + 10, sizeof(uint8_t));
    retlen = websocket_package(data, len, pkg, (len + 10),mask, type);

    if (retlen <= 0)
    {
        free(pkg);
        return 0;
    }

    ret = send(wsc->fd, pkg, retlen, MSG_NOSIGNAL);
    free(pkg);
    return ret;
}
int __attribute__((weak)) OnLogin(struct websocket_client *wsc)
{
    pr_debug("login\n");
    return 0;
}

int __attribute__((weak)) OnMessage(struct websocket_client *wsc, const uint8_t *data, ssize_t len, websocket_data_type type)
{
    int ret = 0;
    if (type == WDT_TXTDATA) {
        if (len) {
            pr_debug("recved msg:%s\n", data);
            while(1) {
                wsc->ubus->jtok = json_tokener_new();
                json_object *msg = json_tokener_parse_ex(wsc->ubus->jtok, data, len);

                if (msg) {
                    const char *backend = json_object_get_string(json_object_object_get(msg, "backend"));
                    const char *sid = json_object_get_string(json_object_object_get(msg, "sid"));
                    const char *scope = json_object_get_string(json_object_object_get(msg, "scope"));
                    pr_debug("\nbackend = %s\nsid = %s\nscope = %s\n", backend, sid, scope);
                    if (backend && sid && scope) {
                        json_object *params = json_object_object_get(msg, "msg");
                        if (params) {
                            if (!strcmp(backend, "ubus"))
                                ubus_message(wsc, params, sid, scope);
                            else if (!strcmp(backend, "uci"))
                                uci_message(wsc, params, sid, scope);
                            else
                                response_msg(wsc, -1, "uknown backen");
                        } else {
                            response_msg(wsc, -1, "invalid argument");
                        }
                    }
                    json_object_put(msg);
                }

                json_tokener_free(wsc->ubus->jtok);
                break;
            }
        }
    }
    if (wsc->msg->data)
        free(wsc->msg->data);

    if (wsc->msg)
        free(wsc->msg);

    return 0;
}

int __attribute__((weak)) OnExit(struct websocket_client *wsc)
{

}

struct websocket_client *new_client(void)
{
    struct websocket_client *wsc = malloc(sizeof(struct websocket_client));
    wsc->recv = &websocket_client_recv;
    wsc->send = &websocket_client_send;
    wsc->OnLogin = &OnLogin;
    wsc->OnMessage = &OnMessage;
    wsc->OnExit = &OnExit;
    wsc->ubus = new_ubus(wsc);
    return wsc;
}

static int remove_wsc(struct websocket_server *wss, struct websocket_client *wsc)
{
    wsc->Online = false;
    wsc->isLogin = false;

    if (wsc->OnExit)
        wsc->OnExit(wsc);

    wss->count -= 1;

    _epoll_ctrl(wss->fd_epoll, wsc->fd, 0, EPOLL_CTL_DEL, wsc);

    pr_debug("close client fd\n");
    close(wsc->fd);

    map_remove(wss->map, wsc->hdr->key);

    return 0;
}

int detect_client(struct websocket_server *wss)
{
    struct tcp_info info;
    const char *key;
    map_iter_t iter;
    struct websocket_client *wsc;
loop:
    iter = map_iter(wss->map);

    while(key = map_next(wss->map, &iter))
    {
        void **tmp = map_get(wss->map, key);
        wsc = *tmp;
        if (wsc) {
            if (wsc->Online) {
                if (wsc->exitType != WET_NONE) {
                    remove_wsc(wss, wsc);
                }

                int len = sizeof(info);

                getsockopt(wsc->fd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len);

                if (info.tcpi_state == TCP_CLOSE_WAIT) {
                    remove_wsc(wss, wsc);
                }
            } else {
                remove_wsc(wss, wsc);
            }
        }

    }
    
    if (!key) {
        websocket_delayms(15 * 1000);
        goto loop;
    }
}
