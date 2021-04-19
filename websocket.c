//
// Created by juno on 2021/4/9.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <locale.h>
#include <json-c/json.h>
#include "http_parser.h"
#include "base64.h"
#include "common.h"
#include "package.h"
#include "ubus.h"
#include "hexdump.h"

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

static int response_ping(char *out) {
    time_t now;
    time(&now);
    int ret;

    struct tm *tm = localtime(&now);

    ret = sprintf(out, "%04d-%02d-%02d %02d:%02d:%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    return ret;
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
    wss->tid = pthread_self();

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

static int websocket_client_add_to_tail(struct websocket_server *wss, struct websocket_client *wsc)
{
    struct websocket_server *cur_svr = wss;
    struct websocket_server *next_svr = NULL;
    struct websocket_client *cur_client = cur_svr->wsc;
    struct websocket_client *next_client = NULL;
    while(cur_svr != NULL) {
        next_svr = cur_svr->next;
        if (cur_svr->count >= cur_svr->load) {
            if (next_svr == NULL) {
                struct websocket_server *ws = new_weboskcet_server(cur_svr->path);
                ws->running = true;
                cur_svr->next = ws;
                ws->wsc = wsc;
                cur_svr = ws;
                wss->start_svr(ws, 1024);
                wsc->tid = wss->tid;
                goto out;
            } else {
                cur_svr = next_svr;
            }
        } else {
            if (cur_client == NULL) {
                cur_svr->wsc = wsc;
                cur_svr->count += 1;
                goto out;
            } else {
                while(cur_client != NULL) {
                    next_client = cur_client->next;
                    if (next_client == NULL) {
                        cur_client->next = wsc;
                        cur_svr->count += 1;
                        goto out;
                    } else {
                        cur_client = next_client;
                    }
                }
            }
        }
	if (next_svr)
	    cur_svr = next_svr;
    }

out:
    _epoll_ctrl(cur_svr->fd_epoll, wsc->fd, EPOLLET | EPOLLIN, EPOLL_CTL_ADD, wsc);
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

    if (strcmp(hdr->connection, "Upgrade"))
        return -1;

    if (strcmp(hdr->upgrade, "websocket"))
        return -1;

    if (atoi(hdr->wsc->ver) < 13){
        return -1;
    }

    if (strcmp(wss->path, hdr->wsc->path)){
        return -1;
    }

    return 0;
}

int websocket_add_client(struct websocket_server *wss, int fd)
{
    char buf[1024] = {0};
    struct http_hdr *http;
    int n = 0;

    if (websocket_waitdata(fd) == 0) {
        pr_err("timeout\n");
        close(fd);
        return -1;
    }

    n = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL);

    if (n < 0) {
        if (errno == EBADFD)
            return -1;
    }

    http = http_parse_request(NULL, buf, n);

    if (isValid_request(wss, http) < 0) {
        free(http->wsc);
        free(http);
        close(fd);
        return -1;
    }


    struct websocket_client *wsc =new_client();
    wsc->hdr = http->wsc;
    wsc->fd = fd;
    wsc->next = NULL;

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

    websocket_client_add_to_tail(wss, wsc);

    return 0;
}


static int websocket_start(struct websocket_server *wss, int load)
{
    if (!wss)
        return -1;
    wss->load = load;
    return new_thread(wss, &websocket_service_thread);
}

struct websocket_server *new_weboskcet_server(const char *path)
{
    struct websocket_server *wss = malloc(sizeof(struct websocket_server));
    strcpy(wss->path, path);
    wss->start_svr = &websocket_start;
    wss->fd_epoll = epoll_create(MAX_CLIENT);
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
    hexdump(buf, n);
#endif
    if (n > 0) {
        char msg[RECV_PKG_MAX] = {0};

        retlen = websocket_unpackage(wsc, buf, n);

        if (retlen == 0 || (retlen < 0 && n - retlen > sizeof(buf)))
        {
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
                        {
                            char buf[1024] = {0};
                            int len = response_ping(buf);
                            wsc->loginTimeout = 300;
                            wsc->send(wsc, buf, len, 0, WDT_PONG);
                        }
                        break;
                    case WDT_PONG:
                        break;
                    case WDT_DISCONN:
                        remove_client(wsc);
                        return 0;
                    default:
                        ret = retlen;
                }
            } else
                ret = -retlen;
        }
    } else {
        if (errno == EBADFD) {
            remove_client(wsc);
            return 0;
        }       
    }

    if (wsc->msg) {
        if (wsc->msg->type == WDT_DISCONN) {
            remove_client(wsc);
            return 0;
        }
    } else {
        remove_client(wsc);
        return 0;
    }

    if (ret > 0)
        wsc->recvBytes += ret > 0 ? ret : (-ret);

    if (wsc->OnMessage)
        wsc->OnMessage(wsc, wsc->msg);

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

static void ubus_process(struct websocket_client *wsc, struct websocket_message *msg)
{
    int ret = 0;
    while(1) {
        wsc->ubus->jtok = json_tokener_new();
        json_object *data = json_tokener_parse_ex(wsc->ubus->jtok, msg->data, msg->len);
        if (!data)
            break;
        const char *sid = json_object_get_string(json_object_object_get(data, "sid"));
        const char *obj = json_object_get_string(json_object_object_get(data, "obj"));
        const char *func = json_object_get_string(json_object_object_get(data, "func"));
        const char *scope = json_object_get_string(json_object_object_get(data, "scope"));
        json_object *params = json_object_object_get(data, "params");

        if (!sid && !obj && !func && !scope)
        {
            response_msg(wsc, -1, "invalid argument");
        } else {
            ret = wsc->ubus->call(wsc->ubus, sid, scope, obj, func, params);
        }
        json_object_put(data);
        json_tokener_free(wsc->ubus->jtok);
        break;
    }
}

int __attribute__((weak)) OnMessage(struct websocket_client *wsc, struct websocket_message *msg)
{
    int ret = 0;
    if (msg->type == WDT_TXTDATA) {
        if (msg->len) {
            pr_debug("recved msg:%s\n", msg->data);
            if (!strcmp(wsc->hdr->path, "/ubus"))
                ubus_process(wsc, msg);
        }
    }

    free(msg->data);
    free(msg);
}

int __attribute__((weak)) OnExit(struct websocket_client *wsc)
{

}

struct websocket_client *new_client(void){
    struct websocket_client *wsc = malloc(sizeof(struct websocket_client));
    wsc->recv = &websocket_client_recv;
    wsc->send = &websocket_client_send;
    wsc->OnLogin = &OnLogin;
    wsc->OnMessage = &OnMessage;
    wsc->OnExit = &OnExit;
    wsc->ubus = new_ubus(wsc);
    return wsc;
}

int detect_client(struct websocket_server *wss)
{
    struct websocket_client *curr_client = NULL;
    struct websocket_client *next_client = NULL;
    struct websocket_client *prev_client = NULL;
    struct websocket_server *curr_wss = NULL;
    struct websocket_server *next_wss = NULL;
    static int timeout = 0;
    int i;
    curr_wss = wss;
    while (1)
    {
        next_wss = curr_wss->next;
        websocket_delayms(500);
        if (curr_wss) {
            if (curr_wss->running) {
                if (curr_wss->count > 0) {
                    curr_client = curr_wss->wsc;
                    while(curr_client != NULL) {
                        next_client = curr_client->next;
                        if (curr_client->Online) {
                            if (curr_client->exitType != WET_NONE) {
                                curr_client->Online = false;
                                curr_client->isLogin = false;
                                _epoll_ctrl(curr_wss->fd_epoll, curr_client->fd, 0, EPOLL_CTL_DEL, curr_client);
                                if (curr_client->OnExit)
                                    curr_client->OnExit(curr_client);

                                curr_wss->count -= 1;
                                close(curr_client->fd);
                                free(curr_client);
                                if (prev_client)
                                    prev_client->next = next_client;
                                else
                                    curr_wss->wsc = next_client;
                            }
                            timeout += 500;
                            if (timeout == 1000) {
                                curr_client->loginTimeout -= 1;
                                if (curr_client->loginTimeout == 0)
                                    curr_client->exitType = WET_LOGIN_TIMEOUT;
                            }
                                
                        }
                        if (next_client) {
                            prev_client = curr_client;
                            curr_client = next_client;
                        }    
                    }
                }
            }
        }
        if (next_wss) {
            curr_wss = next_wss;
        }
    }
}
