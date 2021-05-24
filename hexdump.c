//
// Created by juno on 2021/4/9.
//
#include <stdio.h>
#include "hexdump.h"

typedef unsigned char    cyg_uint8  ;
typedef unsigned int CYG_ADDRWORD;
typedef int __printf_func(const char *fmt, ...);

static void vhexdump_with_offset(__printf_func *pf, cyg_uint8 *p, CYG_ADDRWORD s, cyg_uint8 *base)
{
    int i, c;
    if ((CYG_ADDRWORD)s > (CYG_ADDRWORD)p) {
        s = (CYG_ADDRWORD)s - (CYG_ADDRWORD)p;
    }
    while ((int)s > 0) {
        if (base) {
            (*pf)("%08X: ", (CYG_ADDRWORD)p - (CYG_ADDRWORD)base);
        } else {
            (*pf)("%08X: ", p);
        }
        for (i = 0;  i < 16;  i++) {
            if (i < (int)s) {
                (*pf)("%02X ", p[i] & 0xFF);
            } else {
                (*pf)("   ");
            }
            if (i == 7) (*pf)(" ");
        }
        (*pf)(" |");
        for (i = 0;  i < 16;  i++) {
            if (i < (int)s) {
                c = p[i] & 0xFF;
                if ((c < 0x20) || (c >= 0x7F)) c = '.';
            } else {
                c = ' ';
            }
            (*pf)("%c", c);
        }
        (*pf)("|\n");
        s -= 16;
        p += 16;
    }
}

static void _hexdump(const char *p, unsigned int s, const char *base)
{
    vhexdump_with_offset(printf, p, s, base);
}

void hexdump(const void *dat, size_t len)
{
    _hexdump((const char *)dat, len, 0);
}