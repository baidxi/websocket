//
// Created by juno on 2021/4/9.
//
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <json.h>
#include "websocket.h"
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

const char *error_msg[] = {
    "success",
    "invalid command",
    "invalid argument",
    "method not found",
    "not found",
    "no data",
    "permission denied",
    "not supported",
    "unknown error",
    "conntion failed"
};

int response_msg(struct websocket_client *wsc, int value, const char *str)
{
    int len;
    json_object *req = json_object_new_object();
    json_object *val = json_object_new_int(value);
    json_object *msg = NULL;
    if (str) 
        msg = json_object_new_string(str);
    else
        msg = json_object_new_string(error_msg[value]);
        
    json_object_object_add(req, "value", val);
    json_object_object_add(req, "msg", msg);

    const char *ret = json_object_to_json_string_length(req, NULL, &len);

    return wsc->send(wsc, ret, len, 0, WDT_TXTDATA);
}