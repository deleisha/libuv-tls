
/*//////////////////////////////////////////////////////////////////////////////

 * Copyright (c) 2015  deleisha and other libuv-tls contributors

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
**////////////////////////////////////////////////////////////////////////////*/


#ifndef __UV_TLS_ENGINE_H__
#define __UV_TLS_ENGINE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>




enum uv_tls_state {
    STATE_INIT         = 0x0
    ,STATE_HANDSHAKING = 0x1
    ,STATE_IO          = 0x2 //read or write mode
    ,STATE_CLOSING     = 0x4 // This means closed state also
};

//TODO: improve the error handling
enum uv_tls_error {
    ERR_TLS_ERROR = -1 //use OpenSSL error handling technique for this
    ,ERR_TLS_OK
};


typedef struct tls_engine_s tls_engine;

struct tls_engine_s {
    BIO     *app_bio_; //Our BIO, All IO should be through this
    SSL     *ssl;
    SSL_CTX *ctx;
    BIO     *ssl_bio_; //the ssl BIO used only by openSSL
};

static tls_engine the_engine;
static tls_engine *ptr_engine;



SSL_CTX* get_tls_ctx(void );


#ifdef __cplusplus
}
#endif

#endif 
