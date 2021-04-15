#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <string.h>
#include <getopt.h>
#include "socket.h"
#include "websocket.h"
#include "common.h"

int long_opt;
struct option long_opts[] = {
    {"ip", required_argument, &long_opt, 'i'},
    {"port", required_argument, &long_opt, 'p'},
    {"path", required_argument, &long_opt, 'P'},
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

    conf = malloc(sizeof(struct config));
    memset (conf, 0, sizeof(struct config));

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, &opt_idx)) != -1)
    {
        switch(ch)
        {
            case 0:
                switch(opt_idx)
                {
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
    struct config *conf = parse_args(argc, argv);
    struct websocket_server *cur;
    struct websocket_server *next;
    if (conf == NULL)
        return -1;

    struct socket_server *sock = new_socket(conf->addr, conf->port);

    struct websocket_server *wss = new_weboskcet_server(conf->path);


    

    pr_info("socket create ok\n");


    if (sock)
        sock->start(sock);

    if (wss) {
        sock->wss = wss;
        sock->wss->start_svr(sock->wss, 1024);
    }

    websocket_delayms(1000);


    detect_client(sock->wss);


    return 0;
}
