#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <json.h>
#include "http_parser.h"
#include "base64.h"
#include "common.h"
#include "package.h"
#include "ubus.h"
#include "hexdump.h"
#include "backend.h"


int ubus_message(struct websocket_client *wsc, json_object *msg, const char *sid, const char *scope)
{
    int ret = 0;
    const char *obj = json_object_get_string(json_object_object_get(msg, "obj"));
    const char *func = json_object_get_string(json_object_object_get(msg, "func"));
    json_object *params = json_object_object_get(msg, "params");

    if (!sid || !obj || !func || !scope)
    {
        ret = -1;
        response_msg(wsc, -1, "invalid argument");
    } else {
        ret = wsc->ubus->call(wsc->ubus, sid, scope, obj, func, params);
        if (ret)
            response_msg(wsc, ret, NULL);
    }

    return ret;

}


int uci_message(struct websocket_client *wsc, json_object *msg, const char *sid, const char *scope)
{
    const char *method = json_object_get_string(json_object_object_get(msg, "method"));
    json_object *params = json_object_object_get(msg, "params");

    if (!method || !params) {
        response_msg(wsc, -1, "invalid argument");
        return -1;
    }

    return wsc->ubus->call(wsc->ubus, sid, scope, "uci", method, params);
}
