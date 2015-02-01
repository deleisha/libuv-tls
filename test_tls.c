
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
#include "uv_tls.h"

void on_write(uv_write_t *req, int status)
{
    if(!status && req) {
        free(req);
        req = 0;
    }
}

//Callback for testing
void on_read(uv_tls_t* clnt, int nread, uv_buf_t* dcrypted)
{
    if( nread <= 0 ) {
        if( nread == UV_EOF) {
            uv_tls_close(clnt, NULL);
        }
        else {
            fprintf( stderr, "on_read: %s\n", uv_strerror(nread));
        }
        return;
    }
    uv_write_t *rq = (uv_write_t*)malloc(sizeof(*rq));
    assert(rq != 0);
    uv_tls_write(rq, clnt, dcrypted, on_write);
}

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    memset(buf->base, 0, size);
    buf->len = size;
    assert(buf->base != NULL && "Memory allocation failed");
}



//TEST CODE for the lib
void on_connect(uv_stream_t *server, int status)
{
    if( status ) {
        return;
    }

    uv_tls_t * server_ssl = (uv_tls_t*)server->data;

    //memory being freed at on_close
    uv_tls_t *sclient = (uv_tls_t*) malloc(sizeof(*sclient));
    uv_tls_init(server->loop, sclient);

    sclient->socket_->data = server_ssl;
    int r = uv_tls_accept(server_ssl, sclient);
    if(!r) {
        uv_tls_read(sclient, alloc_cb , on_read);
    }
}


int main()
{
    uv_loop_t *loop = uv_default_loop();

    uv_tls_t *server = (uv_tls_t*)malloc(sizeof *server);
    if(uv_tls_init(loop, server) < 0) {
        free(server);
        server = 0;
        return  -1;
    }

    const int port = 8000;
    struct sockaddr_in bind_addr;
    int r = uv_ip4_addr("0.0.0.0", port, &bind_addr);
    assert(!r);
    r = uv_tcp_bind(server->socket_, (struct sockaddr*)&bind_addr, 0);
    if( r ) {
        fprintf( stderr, "bind: %s\n", uv_strerror(r));
    }

    int rv = uv_tls_listen(server, 128, on_connect);
    if( rv ) {
        fprintf( stderr, "listen: %s\n", uv_strerror(rv));
    }
    printf("Listening on %d\n", port);

    uv_run(loop, UV_RUN_DEFAULT);


    uv_tls_shutdown(server);
    free (server);
    server = 0;

    return EXIT_SUCCESS;
}
