//
// Created by juno on 2021/4/13.
//

#ifndef WEBSOCKET_PACKAGE_H
#define WEBSOCKET_PACKAGE_H
#include <unistd.h>
#include <stdbool.h>
#include "websocket.h"
int websocket_unpackage(struct websocket_client *wsc, uint8_t *data, ssize_t len);
int websocket_package(uint8_t *data, ssize_t len, uint8_t *out, ssize_t maxlen, bool mask, websocket_data_type type);
#endif //WEBSOCKET_PACKAGE_H
