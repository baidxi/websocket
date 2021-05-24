//
// Created by juno on 2021/4/9.
//

#ifndef WEBSOCKET_HTTP_PARSER_H
#define WEBSOCKET_HTTP_PARSER_H

#include <stdio.h>

struct http_hdr {
    char method[4];
    char path[128];
    char version[128];
    char connection[128];
    char upgrade[128];
    char host[128];
    struct websocket_header *wsc;
};

struct http_hdr *http_parse_request(struct http_hdr *hdr, const char *buf, int len);
void build_http_respond(const char *key, ssize_t keylen, char *out);
#endif //WEBSOCKET_HTTP_PARSER_H
