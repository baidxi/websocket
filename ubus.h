#ifndef __UBUS_H
#define __UBUS_H
#include <libubus.h>
#include "websocket.h"
//bool session_access(const char *sid, const char *scope, const char *obj, const char *func);
// int ubus_process(struct blob_attr *);

struct ubus {
    struct ubus_context *ctx;
    struct websocket_client *wsc;
    int (*call)(struct ubus *bus, const char *sid, const char *scope, const char *obj, const char *method, const char *params);
};

struct ubus *new_ubus(struct websocket_client *wsc);

#endif