#include <stdio.h>
#include <assert.h>

#include "evt_tls.h"

typedef struct test_tls_s {
    evt_tls_t *comm;
} test_tls_t;

int test_tls_init(test_tls_t *tst_tls, evt_ctx_t *ctx)
{
    return 0;
}

struct my_data {
    char data[16*1024];
    int sz;
    int stalled;
}test_data;

void on_connect(evt_tls_t *tls, int status)
{
    int r = 0;
    if ( status ) {
	char msg[] = "Hello from event based tls engine\n";
	int str_len = sizeof(msg);
	r =  evt_tls_write(tls, msg, &str_len);
    }
}

int test_tls_connect(test_tls_t *t, evt_conn_cb on_connect)
{
    return evt_tls_connect(t->comm, on_connect);
}

//test nio_handler
int test_nio_hdlr(evt_tls_t *c, void *buf, int sz)
{
    //write to test data as simulation of network write
    memset(&test_data, 0, sizeof(test_data));
    memcpy(test_data.data, buf, sz);
    test_data.sz = sz;
    test_data.stalled = 0;
    return 0;
}

int process_recv_data(test_tls_t *stream )
{
    int r = 0;
    if ( !test_data.stalled ) {
	test_data.stalled = 1;
	r = evt_tls_feed_data(stream->comm, test_data.data, test_data.sz); 
    }
    return r;
}

int test_tls_accept(evt_tls_t *tls)
{
}

int main()
{

    evt_ctx_t tls;
    memset(&tls, 0, sizeof(tls));
    assert(0 == evt_ctx_init(&tls));


    assert(0 == evt_ctx_is_crtf_set(&tls));
    assert(0 == evt_ctx_is_key_set(&tls));
    
    if (!evt_ctx_is_crtf_set(&tls)) {
	evt_ctx_set_crt_key(&tls, "server-cert.pem", "server-key.pem");
    }

    assert( 1 == evt_ctx_is_crtf_set(&tls));
    assert( 1 == evt_ctx_is_key_set(&tls));


    assert(tls.writer == NULL);
    evt_ctx_set_writer(&tls, test_nio_hdlr);
    assert(tls.writer != NULL);

    test_tls_t *clnt_hdl = malloc(sizeof *clnt_hdl);
    assert(clnt_hdl != 0);
    evt_tls_t *clnt = getSSL(&tls );

    clnt_hdl->comm = clnt;


    evt_tls_t *svc = getSSL(&tls);
    SSL_set_accept_state(svc->ssl);
    test_tls_t *svc_hdl = malloc(sizeof(test_tls_t));
    assert(svc_hdl != 0);
    svc_hdl->comm = svc;

    test_tls_connect(clnt_hdl, on_connect);
    process_recv_data(svc_hdl);
    process_recv_data(clnt_hdl);
    process_recv_data(svc_hdl);
    process_recv_data(clnt_hdl);

        
    process_recv_data(svc_hdl);

    free(clnt_hdl);
    free(svc_hdl);
    return 0;
}
