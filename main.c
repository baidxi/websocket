#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <string.h>
#include <getopt.h>
#include "socket.h"
#include "websocket.h"
#include "common.h"

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

int main(int argc, char **argv) {
    int i = 0;
    pr_debug("starting websocket server\n");
    
    struct config *conf = parse_args(argc, argv);

    if (conf == NULL)
        return -1;

    struct socket_server *sock = new_socket(conf->addr, conf->port);
    pr_debug("socket create ok\n");
    struct websocket_server *wss = new_weboskcet_server(conf->path);
    pr_debug("websocket create ok\n");

    if (!sock) {
        pr_err("socket error\n");
        return -1;
    }

    sock->start(sock);

    if (!wss) {
        pr_err("wss failed\n");
        return -1;
    }

    sock->wss = wss;
    sock->wss->start_svr(sock->wss, 1024);
    websocket_delayms(1000);

    detect_client(sock->wss);

    return 0;
}
