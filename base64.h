//
// Created by juno on 2021/4/11.
//

#ifndef WEBSOCKET_BASE64_H
#define WEBSOCKET_BASE64_H
#include <stdbool.h>
int base64_encode(const char *in, int len, bool newline, char *out);
int base64_decode(const char *in, int len, bool newline, char *out);
#endif //WEBSOCKET_BASE64_H
