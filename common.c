//
// Created by juno on 2021/4/9.
//
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/epoll.h>
#include "common.h"

int new_thread(void *args, void *thread_cb)
{
    pthread_t th;
    pthread_attr_t  attr;
    int ret;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&th, &attr, thread_cb, args);
    if (ret != 0)
        pr_err("pthread_create:failed (%s)\n", strerror(errno));

    pthread_attr_destroy(&attr);
    return ret;
}

void _epoll_ctrl(int fd_epoll, int fd, uint32_t event, int ctrl, void *ptr)
{
    struct epoll_event ev;
    ev.events = event;
    if (ptr)
        ev.data.ptr = ptr;
    else
        ev.data.fd = fd;
    if (epoll_ctl(fd_epoll, ctrl, fd, &ev) != 0)
        pr_err("epoll ctrl %d error !!\r\n", ctrl);
}
