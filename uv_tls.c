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

//Auxilary
uv_stream_t* uv_tls_get_stream(uv_tls_t* tls)
{
    return  (uv_stream_t*) &tls->socket_;
}

int uv_tls_init(uv_loop_t *loop, uv_tls_t *strm)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    uv_tcp_init(loop, &strm->socket_);
    strm->socket_.data = strm;

    tls_engine *ng = &(strm->tls_eng);

    ng->ctx = get_tls_ctx();
    ng->ssl = 0;
    ng->ssl_bio_ = 0;
    ng->app_bio_ = 0;
    strm->peer = NULL;
    strm->oprn_state = STATE_INIT;
    strm->rd_cb = NULL;
    strm->on_tls_connection = NULL;
    strm->close_cb = NULL;
    strm->on_tls_connect = NULL;
    strm->write_cb = NULL;
    return 0;
}



int uv__tls_handshake(uv_tls_t* tls, uv_stream_t* client);
int uv__tls_err_hdlr(uv_tls_t* k, uv_stream_t* client, const int err_code);
int uv__tls_read(uv_tls_t* tls, uv_stream_t* client, uv_buf_t* dcrypted, int sz)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    //clean the slate
    memset( dcrypted->base, 0, sz);
    int rv = SSL_read(tls->tls_eng.ssl, dcrypted->base, sz);
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
    uv_tls_t *caller = (uv_tls_t*) client->data;
    assert(caller != NULL);

    uv_tls_t *parent = CONTAINER_OF(client, uv_tls_t, socket_);
    
    assert( parent != NULL);

    if( nread <= 0 ) {
        //caller->rd_cb(caller->peer, nread, (uv_buf_t*)buf);
        caller->rd_cb(parent, nread, (uv_buf_t*)buf);
    }
    else {
        BIO_write( caller->tls_eng.app_bio_, buf->base, nread);
        uv__tls_read(caller, client, (uv_buf_t*)buf, nread);
    }
    free(buf->base);
}

void stay_uptodate(uv_tls_t *sserver, uv_stream_t* client, uv_alloc_cb uv__tls_alloc)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    int pending = BIO_pending(sserver->tls_eng.app_bio_);
    if( pending > 0) {
        //Need to free the memory
        uv_buf_t mybuf;

        if(uv__tls_alloc) {
            uv__tls_alloc((uv_handle_t*)client, pending, &mybuf);
        }

        int rv = BIO_read(sserver->tls_eng.app_bio_, mybuf.base, pending);
        assert( rv > 0 );

        uv_try_write(client, &mybuf, 1);
        free(mybuf.base);
    }
}

static void uv__tls_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    buf->base = (char*)malloc(size);
    assert(buf->base != NULL && "Memory allocation failed");
    buf->len = size;
}



//handle only non fatal error
int uv__tls_err_hdlr(uv_tls_t* k, uv_stream_t* client, const int err_code)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    if(err_code > 0) {
        return err_code;
    }

    switch (SSL_get_error(k->tls_eng.ssl, err_code)) {
        case SSL_ERROR_NONE: //0
        case SSL_ERROR_SSL:  // 1
            ERR_print_errors_fp(stderr);
            //don't break, flush data first

        case SSL_ERROR_WANT_READ: // 2
        case SSL_ERROR_WANT_WRITE: // 3
        case SSL_ERROR_WANT_X509_LOOKUP:  // 4
            stay_uptodate(k, client, uv__tls_alloc);
            break;
        case SSL_ERROR_ZERO_RETURN: // 5
            ERR_print_errors_fp(stderr);
        case SSL_ERROR_SYSCALL: //6
            ERR_print_errors_fp(stderr);
        case SSL_ERROR_WANT_CONNECT: //7
            ERR_print_errors_fp(stderr);
        case SSL_ERROR_WANT_ACCEPT: //8
            ERR_print_errors_fp(stderr);
        default:
            return err_code;
    }
    return err_code;
}


//Need to beef up once client is ready
int uv__tls_close(uv_tls_t* session, uv_stream_t *clnt)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    tls_engine *ng = &(session->tls_eng);
    int rv = SSL_shutdown(ng->ssl);
    uv__tls_err_hdlr(session, clnt, rv);

    if( rv == 0) {
        session->oprn_state = STATE_CLOSING;
        rv = SSL_shutdown(ng->ssl);
        uv__tls_err_hdlr(session, clnt, rv);
    }

    if( rv == 1) {
        session->oprn_state = STATE_CLOSING;
    }

    //SSL_CTX_flush_sessions(session->ctx, time(NULL));
    SSL_free(ng->ssl);
    ng->ssl = NULL;
    BIO_free(ng->app_bio_);

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
    session->close_cb = cb;
    return  uv__tls_close(session->peer, uv_tls_get_stream(session));
}


int uv__tls_handshake(uv_tls_t* tls, uv_stream_t* client)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    if( tls->oprn_state & STATE_IO) {
        return 1;
    }
    int rv = 0;
    rv = SSL_do_handshake(tls->tls_eng.ssl);
    uv__tls_err_hdlr(tls, client, rv);
    tls->oprn_state = STATE_HANDSHAKING;

    if(rv == 1) {
        fprintf(stderr, "Handshaking done\n");
        tls->oprn_state = STATE_IO;
        if(tls->on_tls_connect) {
            assert(tls->con_req);
            tls->on_tls_connect(tls->con_req, 0);
        }
    }
    return rv;
}

int uv_tls_shutdown(uv_tls_t* session)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    assert( session != NULL && "Invalid session");

    SSL_CTX_free(session->tls_eng.ctx);
    session->tls_eng.ctx = NULL;

    return 0;
}

uv_buf_t encode_data(uv_tls_t* sessn, uv_buf_t *data2encode)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    //this should give me something to write to client
    int rv = SSL_write(sessn->tls_eng.ssl, data2encode->base, data2encode->len);

    size_t pending = 0;
    uv_buf_t encoded_data;
    if( (pending = BIO_ctrl_pending(sessn->tls_eng.app_bio_) ) > (size_t)0 ) {

        encoded_data.base = (char*)malloc(pending);
        encoded_data.len = pending;

        rv = BIO_read(sessn->tls_eng.app_bio_, encoded_data.base, pending);
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

    const uv_buf_t data = encode_data(self, buf);

    int rv = uv_write(req, uv_tls_get_stream(client), &data, 1, on_tls_write);
    free(data.base);
    return rv;
}


int uv_tls_read(uv_tls_t* sclient, uv_alloc_cb uv__tls_alloc, tls_rd_cb on_read)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    uv_tls_t* caller = (uv_tls_t*)sclient->peer;
    assert(caller != NULL);
    
    sclient->socket_.data = caller;
    caller->rd_cb = on_read;
  //clean the slate, delete from here, if it does not work
   // int rd_size = SSL_pending(caller->ssl);
 //   uv_buf_t dcrypted;
//    uv__tls_alloc(sclient->socket_, rd_size, &dcrypted);
//    int rv = SSL_read(caller->ssl, dcrypted->base, rd_size);
//    assert( rv == rd_size);

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
        uv_read_start((uv_stream_t*)&sclnt->socket_, uv__tls_alloc, on_tcp_read);
    }
}

int uv_tls_connect(
      uv_connect_t *req,
      uv_tls_t* hdl, const struct sockaddr* addr,
      uv_connect_cb cb)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    tls_engine *tls_ngin = &(hdl->tls_eng);

    tls_ngin->ssl = SSL_new(tls_ngin->ctx);
    if(!tls_ngin->ssl) {
        return ERR_TLS_ERROR;
    }

    //set in client mode
    SSL_set_connect_state(hdl->tls_eng.ssl);
    //use default buf size for now.
    if( !BIO_new_bio_pair(&(tls_ngin->ssl_bio_), 0, &(tls_ngin->app_bio_), 0)) {
        return ERR_TLS_ERROR;
    }
    SSL_set_bio(tls_ngin->ssl, tls_ngin->ssl_bio_, tls_ngin->ssl_bio_);

    hdl->on_tls_connect = cb;
    hdl->con_req = req;

    hdl->peer = hdl;
    return uv_tcp_connect(req, &(hdl->socket_), addr, on_tcp_conn);
}

int uv_tls_accept(uv_tls_t* server, uv_tls_t* client)
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);
    uv_stream_t* clnt = uv_tls_get_stream(client);
    assert(clnt != 0);

    int rv = uv_accept( uv_tls_get_stream(server), clnt);
    if (rv < 0) {
        return rv;
    }

    server->peer = client;
    client->peer = server;

    tls_engine *tls_ngin = &(server->tls_eng);

    tls_ngin->ssl = SSL_new(tls_ngin->ctx);
    if(!tls_ngin->ssl) {
        return ERR_TLS_ERROR;
    }
    SSL_set_accept_state(tls_ngin->ssl);
    //use default buf size for now.
    if( !BIO_new_bio_pair(&(tls_ngin->ssl_bio_), 0, &(tls_ngin->app_bio_), 0)) {
        return ERR_TLS_ERROR;
    }
    SSL_set_bio(tls_ngin->ssl, tls_ngin->ssl_bio_, tls_ngin->ssl_bio_);

    uv_read_start((uv_stream_t*)&client->socket_, uv__tls_alloc, on_tcp_read);
    //TODO: handle this
    return 0;
}
/*
void on_connect(uv_stream_t* strm, int status)
{
    uv_tls_t *parent = CONTAINER_OF(strm, uv_tls_t, socket_);
    if( status != 0) {
        parent->on_tls_connection(parent, status);
    }
    else {
        //TODO: Error handling
        parent->ssl = SSL_new(parent->ctx);
        if(!parent->ssl) {
            return ;
        }
        SSL_set_accept_state(parent->ssl);
        //use default buf size for now.
        if( !BIO_new_bio_pair(&(parent->ssl_bio_), 0, &(parent->app_bio_), 0)) {
            return ;
        }
        SSL_set_bio(parent->ssl, parent->ssl_bio_, parent->ssl_bio_);
    }
    parent->on_tls_connection(parent, status);
}
*/
int uv_tls_listen(uv_tls_t *server,
    const int backlog,
    uv_connection_cb on_new_connect )
{
    fprintf(stderr, "Entering %s\n", __FUNCTION__);

    uv_stream_t *strm = uv_tls_get_stream(server);
    assert(strm != NULL);

    //server->on_tls_connection = on_new_connect;

    return uv_listen( strm, backlog, on_new_connect);
}
