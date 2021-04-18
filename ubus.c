#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include "ubus.h"
#include "common.h"

struct ubus_context *ctx;
enum {
    SES_ACCESS,
    __SES_MAX,
};

static const struct blobmsg_policy ses_policy[__SES_MAX] = {
    [SES_ACCESS] = {
        .name = "access",
        .type = BLOBMSG_TYPE_BOOL
    }
};

static void session_access_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[__SES_MAX];
    bool *allow = (bool *)req->priv;

    if (!msg)
        return ;

    blobmsg_parse(ses_policy, __SES_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[SES_ACCESS])
        *allow = blobmsg_get_bool(tb[SES_ACCESS]);
}

static bool session_access(struct ubus_context *ctx, const char *sid, const char *obj, const char *func)
{
    uint32_t id;
    bool     allow = false;
    static   struct blob_buf req;

    if (ubus_lookup_id(ctx, "session", &id))
        return false;

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "ubus_rpc_session", sid);
    blobmsg_add_string(&req, "object", obj);
    blobmsg_add_string(&req, "function", func);

    ubus_invoke(ctx, id, "access", req.head, session_access_cb, &allow, 500);

    return allow;
}

static void ubus_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct websocket_client *wsc = req->priv;
    if (!msg)
        return;

    const char *ret = blobmsg_format_json(msg, true);
    pr_debug("\nret=%s\n", ret);
    if (ret)
        response_msg(wsc, 0, ret);
}

int ubus_call(struct ubus *bus, const char *sid, const char *scope, const char *obj, const char *func, json_object *params)
{
    uint32_t id;
    static struct blob_buf buf;

    if (ubus_lookup_id(bus->ctx, obj, &id))
        return UBUS_STATUS_NOT_FOUND;

    if (!session_access(bus->ctx, sid, obj, func))
    {
        return response_msg(bus->wsc, -1, "Access denied");
    }

    pr_debug("access %s %s scope=%s\n", obj, func, scope);

    blob_buf_init(&buf, 0);

    if (params)
        blobmsg_add_object(&buf, params);

    return ubus_invoke(bus->ctx, id, func, buf.head, ubus_call_cb, bus->wsc, 500);
}

struct ubus *new_ubus(struct websocket_client *wsc)
{
    struct ubus *ubus = malloc(sizeof(struct ubus));
    if (!ubus)
        return NULL;

    ubus->ctx = ubus_connect(NULL);
    ubus->wsc = wsc;
    ubus->call = &ubus_call;
    return ubus;
}
