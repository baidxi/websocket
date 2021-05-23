//
// Created by juno on 2021/4/13.
//
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "package.h"
#include "common.h"
#include "hexdump.h"

int websocket_unpackage(struct websocket_client *wsc, uint8_t *data, ssize_t len)
{
    int ret = 0;
    unsigned  char *out = NULL;
    struct websocket_message *msg = NULL;
    struct websocket_data_hdr *hdr = NULL;
    if (len < 2)
        return ret;

    hdr = data;

    if (!hdr->fin)
        return ret;

    msg = malloc(sizeof(struct websocket_message));
    if (!msg)
        return ret;

    memset(msg, 0, sizeof(struct websocket_message));

    switch(hdr->opcode) {
        case 0x00:
            msg->type = WDT_MINDATA;
            break;
        case 0x01:
            msg->type = WDT_TXTDATA;
            break;
        case 0x02:
            msg->type = WDT_BINDATA;
            break;
        case 0x08:
            msg->type = WDT_DISCONN;
            break;
        case 0x09:
            msg->type = WDT_PING;
            break;
        case 0x0a:
            msg->type = WDT_PONG;
        default:
        {
            pr_debug("unknow msg type\n");
            free(msg);
            return ret;
        }
    }

    if (hdr->mask) {
        if (hdr->payload == 126) {
            if (len < 4)
                return ret;
            msg->len = __builtin_bswap16(hdr->ext16.payload);

            out = malloc(msg->len);
            memset(out, 0, msg->len);
            int i, m = 0;
            for (i = 0, m = 0; i < msg->len; i++, m++) {
                if (m == 4)
                    m = 0;

                if (m < 2)
                    out[i] = hdr->ext64.data[i + 2] ^ hdr->ext16.maskkey[m + 2];
                else
                    out[i] = hdr->ext64.data[i + 2] ^ hdr->ext64.maskkey[m - 2];
            }
        } else if (hdr->payload == 127) {
            if (len < 10)
                return ret;
            msg->len = __builtin_bswap32(hdr->ext64.payload[1]);
            out = malloc(msg->len);
            memset(out, 0, msg->len);
            int i, m = 0;
            for (i = 0, m = 0; i < msg->len; i++, m++) {
                if (m == 4)
                    m = 0;

                out[i] = hdr->data[i] ^ hdr->maskkey[m];
            }
        } else {
            msg->len = hdr->payload;
            out = malloc(hdr->payload);
            memset(out, 0, hdr->payload);
            int i, m = 0;
            for (i = 0, m = 0; i < hdr->payload; i++, m++) {
                if (m == 4)
                    m = 0;

                out[i] = hdr->ext16.data[i + 4] ^ hdr->ext16.maskkey[m];
            }
        }
    } else {
        if (len < 6)
            return -(6 + hdr->payload - len);

        msg->len = hdr->payload;

        out = malloc(hdr->payload);
        int i;
        for (i = 0; i < hdr->payload; i++) {
            out[i] = hdr->ext16.data[i];
        }
    }
    out[msg->len] = '\0';
    msg->data = out;
    wsc->msg = msg;

    return msg->len;

}

int websocket_package(uint8_t *data, ssize_t len, uint8_t *out, ssize_t maxlen, bool mask, websocket_data_type type)
{

    int i, pkglen = 0;
    uint8_t *maskkey = NULL;
    uint32_t maskcount = 0;

    if (maxlen < 2)
        return -1;

    switch(type) {
        case WDT_MINDATA:
            *out++ = 0x80;
            break;
        case WDT_TXTDATA:
            *out++ = 0x81;
            break;
        case WDT_BINDATA:
            *out++ = 0x82;
            break;
        case WDT_DISCONN:
            *out++ = 0x88;
            break;
        case WDT_PING:
            *out++ = 0x89;
            break;
        case WDT_PONG:
            *out++ = 0x8a;
        default:
            return -1;
    }
    pkglen += 1;

    if (mask)
        *out = 0x80;

    if (len < 126)
    {
        *out++ |= (len & 0x7f);
        pkglen += 1;
    } else if (len < 0xffff + 1) {
        if (maxlen < 4)
            return -1;

        *out++ |= 0x7e;
        *out++ = (uint8_t)((len >> 8) & 0xff);
        *out++ = (uint8_t)((len >> 0) & 0xff);
        pkglen += 3;
    } else {
        if (maxlen < 10)
            return -1;

        *out++ |= 0x7f;
        *out++ = 0;
        *out++ = 0;
        *out++ = 0;
        *out++ = 0;
        *out++ = (uint8_t)((len >> 24) & 0xff);
        *out++ = (uint8_t)((len >> 16) & 0xff);
        *out++ = (uint8_t)((len >> 8) & 0xff);
        *out++ = (uint8_t)((len >> 0) & 0xff);
        pkglen += 9;
    }

    if (mask)
    {
        if (maxlen < pkglen + len + 4)
            return -1;

        maskkey = getrandomstring(4);
        *out++ = maskkey[0];
        *out++ = maskkey[1];
        *out++ = maskkey[2];
        *out++ = maskkey[3];
        pkglen += 4;

        for (i = 0, maskcount = 0; i < len; i++, maskcount++)
        {
            if (maskcount == 4)
                maskcount = 0;

            *out++ = maskkey[maskcount] ^ data[i];
        }
        pkglen += i;
        *out = '\0';
        free(maskkey);
    } else {
        if (maxlen < pkglen + len)
            return -1;

        for (i = 0; i < len; i++)
            *out++ = data[i];

        pkglen += i;

        *out = '\0';
    }

    return pkglen;
}