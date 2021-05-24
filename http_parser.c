//
// Created by juno on 2021/4/9.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "http_parser.h"
#include "websocket.h"
#include "common.h"
#include "hexdump.h"

static int get_option_value(char *dest, const char *src, const char *opt, char needle)
{
    int offset = 0;
    if (opt) {
        int len = strlen(opt);
        char *tmp = strstr(src, opt);
        if(tmp)
            while(tmp[offset + len] != needle) {
                dest[offset] = tmp[offset + len];
                offset++;
            }
        dest[offset] = '\0';
        if (dest[0] == 0x20) {
            offset = 0;
            while(dest[offset] != '\0') {
                dest[offset] = dest[offset + 1];
                offset++;
            }
            dest[offset +1] = '\0';
        }
    } else {
        while(src[offset] != needle) {
            dest[offset] = src[offset];
            offset++;
        }
        dest[offset] = '\0';
    }
    return offset;
}

struct http_hdr *http_parse_request(struct http_hdr *hdr, const char *buf, int len)
{
    int offset = 0;
    if (hdr == NULL)
        hdr = malloc(sizeof(struct http_hdr));

    memset(hdr, 0, sizeof(struct http_hdr));
#ifdef DEBUG
    hexdump(buf, len);
#endif
    get_option_value(hdr->method, buf, NULL, 0x20);
    get_option_value(hdr->path, buf+strlen(hdr->method)+1, NULL, 0x20);
    get_option_value(hdr->connection, buf, "Connection: ", '\r');
    pr_debug("connection = %s\n", hdr->connection);
    if (strstr(hdr->connection, "Upgrade"))
    {
        get_option_value(hdr->upgrade, buf, "Upgrade: ", '\r');
        if (!strcmp(hdr->upgrade, "websocket")) {
            struct websocket_header *wsc = malloc(sizeof (struct websocket_header));
            if (wsc) {
                memset(wsc, 0, sizeof(struct websocket_header));
                get_option_value(&wsc->ver, buf, "Sec-WebSocket-Version: ", '\r');
                get_option_value(&wsc->key, buf, "Sec-WebSocket-Key: ", '\r');
                strcpy(wsc->path, hdr->path);
                hdr->wsc = wsc;
            }
        }
    }
    if (hdr->wsc)
        get_option_value(hdr->version, buf, hdr->wsc->path, '\r');
    
    return hdr;
}

void build_http_respond(const char *key, ssize_t keylen, char *out)
{
    const char template[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Server: Microsoft-HTTPAPI/2.0\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "%s\r\n\r\n";
    time_t now;
    struct tm *tm_now;
    char timestr[256] = {0};
    char responseshakekey[256] = {0};

    buildResponseShakekey(key, keylen, responseshakekey);
    time(&now);
    tm_now = localtime(&now);
    strftime(timestr, sizeof(timestr), "Date: %a, %d %b %Y %T %Z", tm_now);
    sprintf(out, template, responseshakekey, timestr);
}
