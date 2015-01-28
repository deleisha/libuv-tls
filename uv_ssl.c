
/*//////////////////////////////////////////////////////////////////////////////
 * The MIT License (MIT)

 * Copyright (c) 2015  deleisha <dlmeetei@gmail.com>

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
#include "uv_ssl.h"

static void ssl_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}


//Need to enhance
static int uv__ssl_verify_peer(int ok, X509_STORE_CTX* ctx)
{
    return 1;
}


//shutdown the ssl session then stream
int uv_ssl_close(uv_ssl_t* session, ssl_close_cb cb)
{
//    if( !SSL_shutdown(session->ssl)) {
//    }
//    session->close_cb = cb;
    //TODO: callback
    uv_close( (uv_handle_t*)uv_ssl_get_stream(session), NULL);
    return 0;
}




/*
 * Assumes the name and key of the server
 * This forces users to create/deploy their certificate and key
 * by the same name as menioned below. 
 * TODO: improve this and give usr a flexible way 
*/
#define CERTFILE "server-cert.pem"
#define KEYFILE "server-key.pem"

static int uv_ssl_ctx_init(uv_ssl_t* tls)
{
    //Currently we support only TLS, No DTLS
    //TODO: Enhance it later to work for both, should be easy
    tls->ctx = SSL_CTX_new(SSLv23_method());
    if(!tls->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_SSLv3);
//    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_TLSv1);
//    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_TLSv1_1);
//


    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY |
         SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER     |
         SSL_MODE_ENABLE_PARTIAL_WRITE);




    SSL_CTX_set_mode(tls->ctx, SSL_MODE_RELEASE_BUFFERS);

    int r = 0;
    //TODO: Change this later, no hardcoding 
    r = SSL_CTX_set_cipher_list(tls->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if(r != 1) {
        ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, uv__ssl_verify_peer);


    /* certificate file; contains also the public key
     * */
    r = SSL_CTX_use_certificate_file(tls->ctx, CERTFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        ERR_print_errors_fp(stderr);
    }

    r = SSL_CTX_use_PrivateKey_file(tls->ctx, KEYFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        ERR_print_errors_fp(stderr);
    }

    r = SSL_CTX_check_private_key(tls->ctx);
    if(r != 1)
    {
        ERR_print_errors_fp(stderr);
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
        return -1;
    }

    //use default buf size for now.
    if( !BIO_new_bio_pair(&(strm->ssl_bio_), 0, &(strm->app_bio_), 0)) {
        return  -1;
    }


    SSL_set_bio(strm->ssl, strm->ssl_bio_, strm->ssl_bio_);

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
    CRYPTO_cleanup_all_ex_data();
}

void uv__ssl_write_cb(uv_write_t *req, int status)
{
    if(!status && req) {
        free(req);
        req = 0;
    }
}



/*
Read data from application side of BIO and write it to the connection(network)
*/
void stay_uptodate(uv_ssl_t *sserver, uv_stream_t* client, uv_alloc_cb uv__ssl_alloc)
{
    size_t pending = 0;
    if( (pending = BIO_ctrl_pending(sserver->app_bio_) ) > (size_t) 0)
    {
        uv_buf_t mybuf;
        if(uv__ssl_alloc) {
            uv__ssl_alloc((uv_handle_t*)client, pending, &mybuf);
        }

        int rv = BIO_read(sserver->app_bio_, mybuf.base, pending);
        assert( rv > 0 );

        uv_write_t * req = (uv_write_t*)malloc(sizeof *req);
        uv_write(req, (uv_stream_t*)client, &mybuf, 1, uv__ssl_write_cb);
        //write to client BIO
        
        if( mybuf.base ) {
            free(mybuf.base);
            mybuf.base = 0;
        }
    }
}

static void uv__ssl_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    assert(buf->base != NULL && "Memory allocation failed");
    memset(buf->base, 0, size);
    buf->len = size;
}


//handle only non fatal error
int uv__ssl_err_hdlr(uv_ssl_t* k, uv_stream_t* client, const int err_code)
{
    if(err_code > 0) {
        return err_code;
    }

    switch (SSL_get_error(k->ssl, err_code)) {
        case SSL_ERROR_NONE: //0 
        case SSL_ERROR_SSL:  // 1
            //don't break, flush data first

        case SSL_ERROR_WANT_READ: // 2
        case SSL_ERROR_WANT_WRITE: // 3
        case SSL_ERROR_WANT_X509_LOOKUP:  // 4
            stay_uptodate(k, client, uv__ssl_alloc);
            break;
        case SSL_ERROR_ZERO_RETURN: // 5
        case SSL_ERROR_SYSCALL: //6
        case SSL_ERROR_WANT_CONNECT: //7 
        case SSL_ERROR_WANT_ACCEPT: //8
        default:
            return err_code;
    }
    return err_code;
}

int uv__ssl_handshake(uv_ssl_t* ssl_s, uv_stream_t* client)
{
    assert(ssl_s);
    if ( ssl_s->op_state & STATE_IO) {
        return 1; //1 connotates handshakes is done, Need reporting
    }
    
    int rv = SSL_do_handshake(ssl_s->ssl);
    ssl_s->op_state = STATE_HANDSHAKING;

    if(rv == 1) {
        //flush any pending data
        ssl_s->op_state = STATE_IO;
        stay_uptodate(ssl_s, client, uv__ssl_alloc);
        return 1;
    }
    uv__ssl_err_hdlr(ssl_s, client, rv);

    //handshake take multiple trip, Check if it completed now
    if(ssl_s->op_state == STATE_HANDSHAKING) {
        SSL_do_handshake(ssl_s->ssl);
    }
    return rv;
}

int uv__ssl_read(uv_ssl_t* srvr, uv_stream_t* client, uv_buf_t* dcrypted, int sz)
{
    assert(srvr);


    //check if handshake was complete
    if( !(srvr->op_state & STATE_IO)) {
        uv__ssl_handshake(srvr, client);
    }
    
    int rv = SSL_read(srvr->ssl, dcrypted->base, sz);

    uv__ssl_err_hdlr(srvr, client, rv);
    dcrypted->len = rv;
    srvr->rd_cb(srvr->peer, rv, dcrypted);

    return rv;
}

//call back for uv_close
static void on_close(uv_handle_t* handle)
{
    free(handle);
    handle = 0;
}


void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    //TODO: handle the error well
    if( nread <= 0 ) {
        if (nread == UV_EOF) {
            fprintf(stderr, "read_cb: closed client connection\n");
        }
        else {
            fprintf(stderr, "read_cb: Read Error  %s\n", uv_strerror(nread));
        }
        uv_close((uv_handle_t*) client, NULL /*on_close*/);
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

int uv_ssl_shutdown(uv_ssl_t* session)
{
    if(!session) {
        return -1;
    }

    free(session->socket_);
    session->socket_ = NULL;

    SSL_free(session->ssl);
    session->ssl = NULL;

    SSL_CTX_free(session->ctx);
    session->ctx = NULL;

    BIO_free(session->app_bio_);
    uv__ssl_end();
    return 0;
}

//write to ssl session
int uv__ssl_write(uv_ssl_t* ssl_s, uv_stream_t* client, uv_buf_t *data2write)
{
    assert(ssl_s);

    //check if handshake was complete
    if( !(ssl_s->op_state & STATE_IO )) {
        uv__ssl_handshake(ssl_s, client);
    }

    //this should give me something to write to client
    int rv = SSL_write(ssl_s->ssl, data2write->base, data2write->len);
    uv__ssl_err_hdlr(ssl_s, client, rv);

    int pending = 0;
    if( (pending = BIO_pending(ssl_s->app_bio_) ) > 0)
    {
        rv = BIO_read(ssl_s->app_bio_, data2write->base, pending);
        data2write->base[rv] = '\0';
        data2write->len = rv;
    }

    return rv;
}

int uv_ssl_write(uv_write_t* req, uv_ssl_t *client, uv_buf_t *buf, uv_write_cb uv_ssl_write_cb)
{

    uv_ssl_t* srvr = (uv_ssl_t*)client->peer;
    assert(srvr);
    uv__ssl_write(srvr, uv_ssl_get_stream(client), buf);

    return uv_write(req, uv_ssl_get_stream(client), buf, 1, uv_ssl_write_cb);
}


int uv_ssl_read(uv_ssl_t* sclient, uv_alloc_cb uv__ssl_alloc , ssl_rd_cb on_read)
{
    assert( sclient != NULL);

    //extract the ssl to read from
    uv_ssl_t* srvr_ssl = (uv_ssl_t*)sclient->peer;
    assert(srvr_ssl);

    //srvr_ssl->socket_->data = sclient;
    srvr_ssl->rd_cb = on_read;

    return uv_read_start(uv_ssl_get_stream(sclient), uv__ssl_alloc, on_tcp_read);
}


int uv_ssl_accept(uv_ssl_t* server, uv_ssl_t* client)
{
    assert( server != 0);

    uv_stream_t* stream = uv_ssl_get_stream(client);
    assert(stream != 0);

    int r = uv_accept( uv_ssl_get_stream(server), stream);
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
    //set the ssl for listening mode
    SSL_set_accept_state(server->ssl);
    uv_stream_t *strm = uv_ssl_get_stream(server);

    strm->data = server;
    assert( on_connect);
    return uv_listen( strm, backlog, on_connect);
}
