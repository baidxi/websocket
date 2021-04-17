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

static bool session_access(const char *sid, const char *scope, const char *obj, const char *func)
{
    uint32_t id;
    bool allow = false;
    static struct blob_buf req;

    ctx = ubus_connect(NULL);

    if (!ctx || !obj || ubus_lookup_id(ctx, "session", &id))
        goto out;


    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "ubus_rpc_session", sid);
    blobmsg_add_string(&req, "scope", scope);
    blobmsg_add_string(&req, "object", obj);
    blobmsg_add_string(&req, "function", func);

    ubus_invoke(ctx, id, "access", req.head, session_access_cb, &allow, 500);

out:

    return allow;

}

static void ubus_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct websocket_client *wsc = req->priv;
    if (!msg)
        return;

    const char *ret = blobmsg_format_json(msg, 0);

    if (ret)
        wsc->send(wsc, ret, strlen(ret), 0, WDT_TXTDATA);
}

int ubus_call(struct ubus *bus, const char *sid, const char *scope, const char *obj, const char *func, const char *params)
{
    uint32_t id;
    bool allow = false;
    static struct blob_buf buf;

    if (UBUS_STATUS_OK != ubus_lookup_id(bus->ctx, obj, &id))
    {
        json_object *ret = json_object_new_object();
        json_object *val = json_object_new_int(UBUS_STATUS_METHOD_NOT_FOUND);
        json_object_object_add(ret, "ret", val);
        const char *str = json_object_to_json_string(ret);
        bus->wsc->send(bus->wsc, str, strlen(str), 0, WDT_TXTDATA); 
        json_object_put(ret);
        return -1;
    }

    if (!(allow = session_access(bus->ctx, scope, obj, func)))
    {
        json_object *ret = json_object_new_object();
        json_object *val = json_object_new_int(UBUS_STATUS_PERMISSION_DENIED);
        json_object_object_add(ret, "ret", val);
        const char *str = json_object_to_json_string(ret);
        bus->wsc->send(bus->wsc, str, strlen(str), 0, WDT_TXTDATA);
        json_object_put(ret);
        return -1;
    }


    blob_buf_init(&buf, 0);
    blobmsg_add_json_from_string(&buf, params);
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
