//
// Created by juno on 2021/4/11.
//
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdbool.h>
#include <string.h>
#include "base64.h"
int base64_encode(const char *in, int len, bool newline, char *out)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());

    if (!newline)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, in, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    BIO_free_all(b64);

    return bptr->length;
}
int base64_decode(const char *in, int len, bool newline, char *out)
{
    BIO *b64 = NULL;
    BIO *bmem = NULL;

    b64 = BIO_new(BIO_f_base64());

    if (!newline)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(in, len);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, out, len);
    BIO_free_all(bmem);

    return 0;

}