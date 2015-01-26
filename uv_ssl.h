/**********************************************************************************
 *   The MIT License (MIT)

 *   Copyright (c) 2015  deleisha <dlmeetei@gmail.com>

 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:

 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.

 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
***********************************************************************************/
#ifndef __UV_SSL_H__
#define __UV_SSL_H__

#ifdef __cplusplus
extern "C" {
#endif




#include "libuv/include/uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
 
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>


enum uv_ssl_state {
    STATE_INIT = 0x0
    ,STATE_HANDSHAKING = 0x1
    ,STATE_READ = 0x2
    ,STATE_WRITE = 0x4
    ,STATE_CLOSING = 0x8 // This means closed state also
};


typedef struct uv_ssl_s uv_ssl_t;

typedef void (*ssl_rd_cb)(uv_ssl_t* h, int nrd, uv_buf_t* dcrypted);

//Most used members are put first
struct uv_ssl_s {
    uv_tcp_t  *socket_; //handle that encapsulate the socket
    BIO       *app_bio_; //This is our BIO, All IO should be through this
    SSL       *ssl;
    void      *data;   // Field for user data, the lib won't use this
    int       op_state; // operational state
    ssl_rd_cb rd_cb;
    uv_ssl_t  *peer; //reference to connected peer
    SSL_CTX   *ctx;
    BIO       *ssl_bio_; //the ssl BIO used only by openSSL
};




/*
 *Initialize the common part of SSL startup both for client and server
 */
int uv_ssl_init(uv_loop_t* loop, uv_ssl_t* stream);
int uv_ssl_listen(uv_ssl_t *server, const int bk, uv_connection_cb on_connect );
int uv_ssl_accept(uv_ssl_t* server, uv_ssl_t* client);
int uv_ssl_read(uv_ssl_t* client, uv_alloc_cb alloc_cb , ssl_rd_cb on_read);
int uv_ssl_write(uv_write_t* req, uv_ssl_t *client, uv_buf_t* buf, uv_write_cb on_write);
int uv_ssl_shutdown(uv_ssl_t* k);


static void ssl_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}


//Need to enhance
static int uv__ssl_verify_peer(int ok, X509_STORE_CTX* ctx)
{
    return 1;
}

/*
 * Assumes the name and key of the server
 * This forces users to create/deploy their certificate and key
 * by the same name as menioned below. 
 * TODO: improve this and give usr a flexible way 
*/
#define CERTFILE "server-cert.pem"
#define KEYFILE "server-key.pem"

static int uv_ssl_ctx_init(uv_ssl_t* k)
{
    //Currently we support only TLS, No DTLS
    //TODO: Enhance it later to work for both, should be easy
    k->ctx = SSL_CTX_new(SSLv23_method());
    if(!k->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    SSL_CTX_set_options(k->ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(k->ctx, SSL_OP_NO_SSLv3);
//    SSL_CTX_set_options(k->ctx, SSL_OP_NO_TLSv1);
//    SSL_CTX_set_options(k->ctx, SSL_OP_NO_TLSv1_1);
//


    SSL_CTX_set_mode(k->ctx, SSL_MODE_RELEASE_BUFFERS);

    int r = 0;
    //TODO: Change this later, no hardcoding 
    r = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if(r != 1) {
        ERR_print_errors_fp(stderr);
        return -2;
    }

    SSL_CTX_set_verify(k->ctx, SSL_VERIFY_NONE, uv__ssl_verify_peer);


    /* certificate file; contains also the public key
     * */
    r = SSL_CTX_use_certificate_file(k->ctx, CERTFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        ERR_print_errors_fp(stderr);
        return -4;
    }

    r = SSL_CTX_use_PrivateKey_file(k->ctx, KEYFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        ERR_print_errors_fp(stderr);
        return -5;
    }

    r = SSL_CTX_check_private_key(k->ctx);
    if(r != 1)
    {
        ERR_print_errors_fp(stderr);
        return -6;
    }

    return 0;
}

int uv_ssl_init(uv_loop_t *loop, uv_ssl_t *strm)
{
    //prepare the ssl engine
    ssl_begin();

    strm->socket_ = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    assert(strm->socket_);
    uv_tcp_init(loop, strm->socket_);

    strm->ctx = 0;
    strm->ssl = 0;
    strm->ssl_bio_ = 0;
    strm->app_bio_ = 0;
    strm->data = 0;
    strm->op_state = STATE_INIT;
    strm->rd_cb = NULL;
    strm->peer = NULL;

    uv_ssl_ctx_init(strm);

    /* create SSL* */
    strm->ssl = SSL_new(strm->ctx);
    if(!strm->ssl) {
        printf("Error: cannot create new SSL*.\n");
        return -1;
    }

    //use default buf size for now.
    if( !BIO_new_bio_pair(&(strm->ssl_bio_), 0, &(strm->app_bio_), 0)) {
        printf("Error: cannot allocate bios.\n");
        return -2;
    }


    SSL_set_bio(strm->ssl, strm->ssl_bio_, strm->ssl_bio_);
    //Move this to Ctx part
    SSL_set_mode( strm->ssl, SSL_MODE_AUTO_RETRY |
            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
            SSL_MODE_ENABLE_PARTIAL_WRITE);

    //TODO:push these parts in listen or connect
    /* either use the server or client part of the
     * protocol */
    //    SSL_set_connect_state(k->ssl);
    return 0;
}

static void uv__ssl_end(void)
{
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
}

void on_write(uv_write_t *req, int status)
{
    if(!status && req) {
        free(req);
        req = 0;
    }
}



/*
Read data from application side of BIO and write it to the connection(network)
*/
void stay_uptodate(uv_ssl_t *sserver, uv_stream_t* client, uv_alloc_cb alloc_cb)
{
    size_t pending = 0;
    if( (pending = BIO_ctrl_pending(sserver->app_bio_) ) > (size_t) 0)
    {
        uv_buf_t mybuf;
        if(alloc_cb) {
            alloc_cb((uv_handle_t*)client, pending, &mybuf);
        }

        int rv = BIO_read(sserver->app_bio_, mybuf.base, pending);
        assert(rv);

        uv_write_t * req = (uv_write_t*)malloc(sizeof *req);
        uv_write(req, (uv_stream_t*)client, &mybuf, 1, on_write);
        //write to client BIO
        
        if( mybuf.base ) {
            free(mybuf.base);
            mybuf.base = 0;
        }
    }
}

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    memset(buf->base, 0, size);
    buf->len = size;
    assert(buf->base != NULL && "Memory allocation failed");
}





//handle only non fatal error
int uv__ssl_err_hdlr(uv_ssl_t* k, uv_stream_t* client, const int err_code)
{
    if(err_code > 0) {
        return err_code;
    }

    switch (SSL_get_error(k->ssl, err_code)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_SSL:
            ERR_print_errors_fp(stderr);
            //don't break, flush data first

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_X509_LOOKUP:
            stay_uptodate(k, client, alloc_cb);
            break;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        default:
            return err_code;
    }
    return err_code;
}

//To avoid function call here, introduce a state enum 
int uv__ssl_handshake(uv_ssl_t* ssl_s, uv_stream_t* client)
{
    assert(ssl_s);
    if ( (ssl_s->op_state & STATE_READ) || (ssl_s->op_state & STATE_WRITE)) {
        return 1; //1 connotates handshakes is done, Need improvement
    }
    
    int rv = SSL_do_handshake(ssl_s->ssl);
    ssl_s->op_state = STATE_HANDSHAKING;

    if(rv == 1) {
        //flush any pending data
        ssl_s->op_state = STATE_READ | STATE_WRITE;
        stay_uptodate(ssl_s, client, alloc_cb);
        return 1;
    }
    uv__ssl_err_hdlr(ssl_s, client, rv);

    if(ssl_s->op_state == STATE_HANDSHAKING) {
        SSL_do_handshake(ssl_s->ssl);
    }
    return rv;
}

int uv__ssl_read(uv_ssl_t* ssl_s, uv_stream_t* client, uv_buf_t* dcrypted, int sz)
{
    assert(ssl_s);


    //check if handshake was complete
    if( !(ssl_s->op_state & (STATE_READ |STATE_WRITE))) {
        uv__ssl_handshake(ssl_s, client);
        //return  -5; //Error handling to be done
    }
    
    int rv = SSL_read(ssl_s->ssl, dcrypted->base, sz);
    dcrypted->len = sz;

    uv__ssl_err_hdlr(ssl_s, client, rv);
    ssl_s->rd_cb(ssl_s->peer, rv, dcrypted);

    return rv;
}

//call back for uv_close
void on_close(uv_handle_t* handle)
{
    free(handle);
    handle = 0;
    fprintf(stderr, "disconnected\n");
}




void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    if( nread <= 0 ) {
        if (nread == UV_EOF) {
            //    uv_close((uv_handle_t*) client, on_close);
            fprintf(stderr, "read_cb: closed client connection\n");
        }
        else {
            fprintf(stderr, "read_cb: Read Error  %s\n", uv_strerror(nread));
        }
        uv_close((uv_handle_t*) client, on_close);
    }
    else {
        uv_ssl_t *s_ssl = (uv_ssl_t*) client->data;
        int rv = BIO_write( s_ssl->app_bio_, buf->base, nread);
        uv__ssl_err_hdlr(s_ssl, client, rv);

        uv__ssl_read(s_ssl, client, (uv_buf_t*)buf, nread);
    }
    if( buf->base) {
        free(buf->base);
    }
}

int uv_ssl_shutdown(uv_ssl_t* k)
{
    if(!k) {
        return -1;
    }

    if(k->socket_) {
        free(k->socket_);
        k->socket_ = 0;
    }

    if(k->ssl) {
        SSL_free(k->ssl);
        k->ssl = NULL;
    }

    if(k->ctx) { 
        SSL_CTX_free(k->ctx);
        k->ctx = NULL;
    }

    if(k->app_bio_) {
        BIO_free(k->app_bio_);
    }
    uv__ssl_end();
    return 0;
}

//write to ssl session
int uv__ssl_write(uv_ssl_t* ssl_s, uv_stream_t* client, uv_buf_t *encrypted)
{
    assert(ssl_s);


    //check if handshake was complete
    if( !(ssl_s->op_state & (STATE_READ |STATE_WRITE))) {
        uv__ssl_handshake(ssl_s, client);
    }

    //this should give me something to write to client
    int rv = SSL_write(ssl_s->ssl, encrypted->base, encrypted->len);
    uv__ssl_err_hdlr(ssl_s, client, rv);

    int pending = 0;
    if( (pending = BIO_pending(ssl_s->app_bio_) ) > 0)
    {
        rv = BIO_read(ssl_s->app_bio_, encrypted->base, pending);
        encrypted->base[rv] = '0';
        encrypted->len = rv;
    }

    return rv;
}

int uv_ssl_write(uv_write_t* req, uv_ssl_t *client, uv_buf_t *buf, uv_write_cb on_write)
{

    uv_ssl_t* s = (uv_ssl_t*)client->socket_->data;
    assert(s);
    uv__ssl_write(s, (uv_stream_t*)client->socket_, buf);

    return uv_write(req, (uv_stream_t*)client->socket_, buf, 1, on_write);
}


int uv_ssl_read(uv_ssl_t* sclient, uv_alloc_cb alloc_cb , ssl_rd_cb on_read)
{
    if(!sclient) {
        return -1;
    }

    //extract the ssl to read from
    uv_ssl_t* srvr_ssl = (uv_ssl_t*)sclient->peer;
    assert(srvr_ssl);
    srvr_ssl->socket_->data = sclient;
    srvr_ssl->rd_cb = on_read;

    return  uv_read_start(
              (uv_stream_t*)sclient->socket_, alloc_cb, on_tcp_read);
}


int uv_ssl_accept(uv_ssl_t* server, uv_ssl_t* client)
{
    assert( server != 0);

    uv_stream_t* stream = (uv_stream_t*)client->socket_;
    assert(stream != 0);

    int r = uv_accept((uv_stream_t*)server->socket_, stream);
    if (r) {
        return r;
    }
    server->peer = client;
    client->peer = server;
    return 0;
}
int uv_ssl_listen(uv_ssl_t *server,
    const int backlog,
    uv_connection_cb on_connect )
{
    //Now set the ssl for listening mode
    SSL_set_accept_state(server->ssl);
    uv_stream_t *strm = (uv_stream_t*)server->socket_;

    strm->data = server;
    assert( on_connect);
    return uv_listen( (uv_stream_t*)strm, backlog, on_connect);
}

#ifdef __cplusplus
}
#endif

#endif 
