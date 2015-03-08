
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


#include "tls_engine.h"
static void tls_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

//Need to enhance
static int uv__tls_verify_peer(int ok, X509_STORE_CTX* ctx)
{
    return 1;
}


/*
 * TODO: improve this and give usr a flexible way 
*/
#define CERTFILE "server-cert.pem"
#define KEYFILE "server-key.pem"

static int uv_tls_ctx_init(tls_engine *tls)
{
    tls_begin();
    //Currently we support only TLS, No DTLS
    tls->ctx = SSL_CTX_new(SSLv23_method());
    if(!tls->ctx) {
        return ERR_TLS_ERROR;
    }
    
    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_SSLv3);

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY |
         SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER     |
         SSL_MODE_ENABLE_PARTIAL_WRITE);

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_RELEASE_BUFFERS);

    int r = 0;
    //TODO: Change this later, no hardcoding 
#define CIPHERS    "ALL:!EXPORT:!LOW"
    r = SSL_CTX_set_cipher_list(tls->ctx, CIPHERS);
    if(r != 1) {
        return ERR_TLS_ERROR;
    }

    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, uv__tls_verify_peer);

    r = SSL_CTX_use_certificate_file(tls->ctx, CERTFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        return ERR_TLS_ERROR;
    }

    r = SSL_CTX_use_PrivateKey_file(tls->ctx, KEYFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        return ERR_TLS_ERROR;
    }

    r = SSL_CTX_check_private_key(tls->ctx);
    if(r != 1) {
        return ERR_TLS_ERROR;
    }
    return ERR_TLS_OK;
}

tls_engine* get_tls_engine(void)
{
    if(ptr_engine) {
        return ptr_engine;
    }
    //TODO: Better error handling
    if( 0 != uv_tls_ctx_init(&the_engine)) {
        return NULL;
    }
    ptr_engine = &the_engine;
    return  ptr_engine;
}

static void uv__tls_end(void)
{
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

void tls_enginge_start(tls_engine * eng)
{

}

void tls_engine_stop(void)
{
    uv__tls_end();
}


inline SSL_CTX* get_tls_ctx(void )
{
    return get_tls_engine()->ctx;
}

/*
Commented out till the tls_eng state machine is completely ready
int feed_engine(tls_engine *eng, void *data, int sz )
{
    return BIO_write(eng->app_bio_, data, sz);
}

int read_app_data(tls_engine *eng, void *dcrypted_data, int sz)
{
    return  SSL_read(eng->ssl, dcrypted_data, sz);
}

int encrypt_data(tls_engine *eng, const void *data2encrypt, int sz)
{
    int rv = SSL_write(eng->ssl, data2encrypt, sz);
    assert(rv == sz);

//    size_t pending = 0;
//    uv_buf_t encoded_data;
//    if( (pending = BIO_ctrl_pending(eng->app_bio_) ) > (size_t)0 ) {

//        encoded_data.base = (char*)malloc(pending);
//        encoded_data.len = pending;

//        rv = BIO_read(eng->app_bio_, encoded_data.base, pending);
//        encoded_data.len = rv;
//    }
    //return encoded_data;
    return 0;
}

//real workhouse for the state machine
void drive_engine(tls_engine *eng)
{
    return;

}
*/
