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


#include "uv_tls.h"


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


//Auxilary
uv_stream_t* uv_tls_get_stream(uv_tls_t* tls)
{
    return  (uv_stream_t*) tls->socket_;
}


/*
 * TODO: improve this and give usr a flexible way 
*/
#define CERTFILE "server-cert.pem"
#define KEYFILE "server-key.pem"

static int uv_tls_ctx_init(uv_tls_t* tls)
{
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

int uv_tls_init(uv_loop_t *loop, uv_tls_t *strm)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    //prepare the ssl engine
    tls_begin();

    strm->socket_ = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    assert(strm->socket_);
    uv_tcp_init(loop, strm->socket_);
    strm->socket_->data = strm;

    strm->ctx = 0;
    strm->ssl = 0;
    strm->ssl_bio_ = 0;
    strm->app_bio_ = 0;
    strm->data = 0;
    strm->oprn_state = STATE_INIT;
    strm->rd_cb = NULL;
    strm->close_cb = NULL;
    strm->write_cb = NULL;
    strm->peer = NULL;

    int rv = uv_tls_ctx_init(strm);
    if( rv != ERR_TLS_OK) {
        return  rv;
    }

    /* create SSL* */
    strm->ssl = SSL_new(strm->ctx);
    if(!strm->ssl) {
        return ERR_TLS_ERROR;
    }

    //use default buf size for now.
    if( !BIO_new_bio_pair(&(strm->ssl_bio_), 0, &(strm->app_bio_), 0)) {
        return ERR_TLS_ERROR;
    }


    SSL_set_bio(strm->ssl, strm->ssl_bio_, strm->ssl_bio_);

    return ERR_TLS_OK;
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


int uv__tls_handshake(uv_tls_t* tls, uv_stream_t* client);
int uv__tls_err_hdlr(uv_tls_t* k, uv_stream_t* client, const int err_code);
int uv__tls_read(uv_tls_t* tls, uv_stream_t* client, uv_buf_t* dcrypted, int sz)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    if( !(tls->oprn_state & STATE_IO)) {
        uv__tls_handshake(tls, client);
    }

    //check again if handshake is completed and proceed to read if so
    if( !(tls->oprn_state & STATE_IO)) {
        return  STATE_HANDSHAKING;
    }

    //clean the slate
    memset( dcrypted->base, 0, sz);
    int rv = SSL_read(tls->ssl, dcrypted->base, sz);

    uv__tls_err_hdlr(tls, client, rv);

    dcrypted->len = rv;
    if( tls->rd_cb) {
        tls->rd_cb(tls->peer, rv, dcrypted);
    }

    return rv;
}
void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_tls_t *self = (uv_tls_t*) client->data;
    assert(self != NULL);

    if( nread <= 0 ) {
        self->rd_cb(self->peer, nread, (uv_buf_t*)buf);
    }
    else {
        BIO_write( self->app_bio_, buf->base, nread);
        uv__tls_read(self, client, (uv_buf_t*)buf, nread);
    }
    free(buf->base);
}

void stay_uptodate(uv_tls_t *sserver, uv_stream_t* client, uv_alloc_cb uv__tls_alloc)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    int pending = BIO_pending(sserver->app_bio_);
    if( pending > 0) {
        uv_buf_t mybuf;

        if(uv__tls_alloc) {
            uv__tls_alloc((uv_handle_t*)client, pending, &mybuf);
        }

        int rv = BIO_read(sserver->app_bio_, mybuf.base, pending);
        assert( rv > 0 );

        uv_try_write(client, &mybuf, 1);
    }
    uv_read_start(client, uv__tls_alloc, on_tcp_read);
}

static void uv__tls_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    buf->base = (char*)malloc(size);
    assert(buf->base != NULL && "Memory allocation failed");
    memset(buf->base, 0, size);
    buf->len = size;
}



//handle only non fatal error
int uv__tls_err_hdlr(uv_tls_t* k, uv_stream_t* client, const int err_code)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
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
            stay_uptodate(k, client, uv__tls_alloc);
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


//Need to beef up once client is ready
int uv__tls_close(uv_tls_t* session, uv_stream_t *clnt)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    int rv = SSL_shutdown(session->ssl);
    uv__tls_err_hdlr(session, clnt, rv);

    if( rv == 0) {
        rv = SSL_shutdown(session->ssl);
        uv__tls_err_hdlr(session, clnt, rv);
    }

    if( rv == 1) {
        session->oprn_state = STATE_CLOSING;
    }

    uv_close( (uv_handle_t*)clnt, NULL);
    if( session->close_cb) {
        session->close_cb(session);
    }

    return rv;
}

//shutdown the ssl session then stream
int uv_tls_close(uv_tls_t* session, tls_close_cb cb)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_tls_t* srvr = session->peer;
    assert(srvr != 0);
    session->close_cb = cb;
    return  uv__tls_close(session, uv_tls_get_stream(session));
}


int uv__tls_handshake(uv_tls_t* tls, uv_stream_t* client)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    if( tls->oprn_state & STATE_IO) {
        return 1;
    }
    
    int rv = SSL_do_handshake(tls->ssl);
    uv__tls_err_hdlr(tls, client, rv);
    tls->oprn_state = STATE_HANDSHAKING;

    if(rv == 1) {
        tls->oprn_state = STATE_IO;
        if(tls->on_tls_connect) {
            assert(tls->con_req);
            tls->on_tls_connect(tls->con_req, 0);
        }
        return rv;
    }

    //handshake take multiple trip, Check if it completed now
    if(!(tls->oprn_state & STATE_IO)) {
        rv = SSL_do_handshake(tls->ssl);
        uv__tls_err_hdlr(tls, client, rv);
    }
    return rv;
}

int uv_tls_shutdown(uv_tls_t* session)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    assert( session != NULL && "Invalid session");

    free(session->socket_);
    session->socket_ = NULL;

    SSL_free(session->ssl);
    session->ssl = NULL;

    SSL_CTX_free(session->ctx);
    session->ctx = NULL;

    BIO_free(session->app_bio_);

    uv__tls_end();
    return 0;
}

uv_buf_t encode_data(uv_tls_t* sessn, uv_stream_t* client, uv_buf_t *data2encode)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    if( !(sessn->oprn_state & STATE_IO )) {
        uv__tls_handshake(sessn, client);
    }
    //ensure if handshake was complete
    assert(sessn->oprn_state & STATE_IO);

    //this should give me something to write to client
    int rv = SSL_write(sessn->ssl, data2encode->base, data2encode->len);

    size_t pending = 0;
    uv_buf_t encoded_data;
    if( (pending = BIO_ctrl_pending(sessn->app_bio_) ) > (size_t)0 ) {

        encoded_data.base = (char*)malloc(pending);
        encoded_data.len = pending;

        rv = BIO_read(sessn->app_bio_, encoded_data.base, pending);
        data2encode->len = rv;
    }
    return encoded_data;
}

int uv_tls_write(uv_write_t* req,
       uv_tls_t *client,
       uv_buf_t *buf,
       tls_write_cb on_tls_write)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    uv_tls_t* self = (uv_tls_t*)client->peer;
    assert(self);
    self->write_cb = on_tls_write;

    const uv_buf_t data = encode_data(self, uv_tls_get_stream(client), buf);

    int rv = uv_write(req, uv_tls_get_stream(client), &data, 1, on_tls_write);
    free(data.base);
    return rv;
}


int uv_tls_read(uv_tls_t* sclient, uv_alloc_cb uv__tls_alloc, tls_rd_cb on_read)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_tls_t* caller = (uv_tls_t*)sclient->peer;
    assert(caller != NULL);
    
    sclient->socket_->data = caller;
    caller->rd_cb = on_read;
    return 0;
}

void on_tcp_conn(uv_connect_t* c, int status)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_tls_t *sclnt = c->handle->data;
    assert( sclnt != 0);
    if(status < 0) {
        sclnt->on_tls_connect(c, status);
    }
    else { //tcp connection established
        uv__tls_handshake(sclnt, uv_tls_get_stream(sclnt));
    }
}

int uv_tls_connect(
      uv_connect_t *req,
      uv_tls_t* hdl, const struct sockaddr* addr,
      uv_connect_cb cb)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    //set in client mode
    SSL_set_connect_state(hdl->ssl);
    hdl->on_tls_connect = cb;
    hdl->con_req = req;

    hdl->peer = hdl;
    return uv_tcp_connect(req, hdl->socket_, addr, on_tcp_conn);
}

int uv_tls_accept(uv_tls_t* server, uv_tls_t* client)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_stream_t* stream = uv_tls_get_stream(client);
    assert(stream != 0);

    int rv = uv_accept( uv_tls_get_stream(server), stream);
    if (rv < 0) {
        return rv;
    }

    server->peer = client;
    client->peer = server;
    uv__tls_handshake(server, uv_tls_get_stream(client));
    //TODO: handle this
    return 0;
}

int uv_tls_listen(uv_tls_t *server,
    const int backlog,
    uv_connection_cb on_connect )
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    //set the ssl for listening mode
    SSL_set_accept_state(server->ssl);

    uv_stream_t *strm = uv_tls_get_stream(server);
    assert(strm != NULL);

    return uv_listen( strm, backlog, on_connect);
}
