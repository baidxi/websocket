#ifndef __BACKEND_H
#define __BACKEND_H
#include <json.h>
int ubus_message(struct websocket_client *wsc, json_object *msg, const char *sid, const char *scope);
int uci_message(struct websocket_client *wsc, json_object *msg, const char *sid, const char *scope);
#endif