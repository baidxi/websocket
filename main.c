#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <string.h>
#include <getopt.h>
#include "socket.h"
#include "websocket.h"
#include "common.h"
#include "hashmap.h"

#ifdef DEBUG
#include <syslog.h>
#endif

struct option long_opts[] = {
    {"ip", required_argument, NULL, 'i'},
    {"port", required_argument, NULL, 'p'},
    {"path", required_argument, NULL, 'P'},
    {0, 0, 0, 0},
};

struct config *parse_args(int argc, char **argv)
{
    int ch;
    int opt_idx;
    const char *short_opts = "i:p:P:";
    struct config *conf = NULL;
    int i = 0;
    if (argc < 4) {
        return NULL;
    }
    pr_debug("start parse args\n");

    conf = malloc(sizeof(struct config));
    memset (conf, 0, sizeof(struct config));

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, &opt_idx)) != -1)
    {
        switch(ch)
        {
            case 0:
                switch(opt_idx)
                {
                    case 0:
                        conf->addr = strdup(optarg);
                        break;
                    case 1:
                        if (atoi(optarg) > 0 && atoi(optarg) < 65535)
                            conf->port = atoi(optarg);
                        else {
                            pr_err("invalid port argument\n");
                            conf->port = 8088;
                        }
                        break;
                    case 2:
                        conf->path = strdup(optarg);

                        break;
                }
            case 'i':
                conf->addr = strdup(optarg);
                break;
            case 'p':
                if (atoi(optarg) > 0 && atoi(optarg) < 65535)
                    conf->port = atoi(optarg);
                else {
                    pr_err("invalid port argument\n");
                    conf->port = 8088;
                }
                break;
            case 'P':
                conf->path = strdup(optarg);

                break;
        }
    }

    return conf;
}
struct socket_server *sock;

static void signal_process(int sig)
{
    if (sig == SIGINT)
    {
        pthread_cancel(sock->wss->tid);
        pthread_cancel(sock->tid);
        const char *key;
        map_iter_t iter;
        struct websocket_client *wsc;
        struct websocket_server *wss = sock->wss;
        while(key = map_next(wss->map, &iter))
        {
            void **tmp = *map_get(wss->map, key);
            wsc = *tmp;
            _epoll_ctrl(wss->fd_epoll, wsc->fd, 0, EPOLL_CTL_DEL, wsc);
            close(wsc->fd);
            free(wsc);
        }

        close(wss->fd_epoll);
        close(wss->fd);
        free(wss);
        close(sock->epoll_fd);
        close(sock->fd);
        free(sock);
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, char **argv) 
{
    int i = 0;
    int ret = 0;
    pr_debug("starting websocket server\n");
    
    struct config *conf = parse_args(argc, argv);

    if (conf == NULL)
        return -1;

    sock = new_socket(conf->addr, conf->port);

    if (!sock) {
        pr_err("socket error\n");
        goto err_out1;
    }

    pr_debug("socket create ok\n");
    ret = sock->start(sock);
    if (ret < 0) {
        pr_err("sock thread start failed:%s\n", strerror(errno));
        goto err_sock;
    }
    struct websocket_server *wss = new_weboskcet_server(conf->path);
    
    if (!wss) {
        pr_err("wss failed\n");
        goto err_sock;
    }
    pr_debug("websocket create ok\n");

    sock->wss = wss;
    if (sock->wss->start_svr(sock->wss, 1024) < 0)
    {
        pr_err("websocket thread start failed:%s\n", strerror(errno));
        pthread_cancel(sock->tid);
        goto err_wss;
    }
    websocket_delayms(1000);
    signal(SIGINT, signal_process);
    free(conf);

    detect_client(sock->wss);

err_wss:
    free(wss);

err_sock:
    free(sock);

err_out1:
    free(conf);
    return -1;
}
