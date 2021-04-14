//
// Created by juno on 2021/4/9.
//

#ifndef WEBSOCKET_COMMON_H
#define WEBSOCKET_COMMON_H
#include <stdio.h>
#define print_help_str(index, help_str) \
do{ \
	fprintf(stderr, "\t--%-10s\t-%c\t%s", long_opts[index].name, long_opts[index].val, help_str); \
}while(0)

#ifdef DEBUG
#define pr_debug(fmt,...) \
    do { \
        fprintf(stderr, "%s %s [%d]", __FILE__, __func__, __LINE__); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    }while(0)


#else
#define pr_debug(fmt,...)

#endif

#define pr_info(fmt, ...) \
    do{ \
        fprintf(stdout, fmt, ##__VA_ARGS__); \
    }while(0)

#define pr_err(fmt,...) \
    do { \
        fprintf(stderr, "%s %s[%d]", __FILE__, __func__, __LINE__); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    }while(0)

#define pr_war(fmt,...) \
    do { \
        fprintf(stderr, "%s %s[%d]", __FILE__, __func__, __LINE__); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    }while(0)

int new_thread(void *args, void *thread_cb);
void _epoll_ctrl(int fd_epoll, int fd, uint32_t event, int ctrl, void *ptr);

#endif //WEBSOCKET_COMMON_H
