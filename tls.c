#include "uv_ssl.h"

//Callback for testing
void on_read(uv_ssl_t* h, int nread, uv_buf_t* dcrypted)
{
    if( nread <= 0 ) {
        return;
    }
    uv_write_t *rq = (uv_write_t*)malloc(sizeof(*rq));
    assert(rq != 0);
    fprintf( stderr, "decrypted = %s", dcrypted->base);
    uv_ssl_write(rq, h, dcrypted, on_write);
}

//TEST CODE for the lib
void on_connect(uv_stream_t *server, int status)
{
    if( status ) {
        return;
    }

    uv_ssl_t * server_ssl = (uv_ssl_t*)server->data;

    //memory being freed at on_close
    uv_ssl_t *sclient = (uv_ssl_t*) malloc(sizeof(*sclient));
    uv_ssl_init(server->loop, sclient);
    //For testing again
    SSL_set_connect_state(sclient->ssl);

    sclient->socket_->data = server_ssl;
    int r = uv_ssl_accept(server_ssl, sclient);
    if(!r) {
        uv_ssl_read(sclient, alloc_cb , on_read);
    }
}


int main()
{
    uv_loop_t *loop = uv_default_loop();

    uv_ssl_t *server = (uv_ssl_t*)malloc(sizeof *server);
    if(uv_ssl_init(loop, server) < 0) {
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

    int rv = uv_ssl_listen(server, 128, on_connect);
    if( rv ) {
        fprintf( stderr, "listen: %s\n", uv_strerror(rv));
    }
    printf("Listening on %d\n", port);

    uv_run(loop, UV_RUN_DEFAULT);


    uv_ssl_shutdown(server);
    free (server);
    server = 0;

    return EXIT_SUCCESS;
}
