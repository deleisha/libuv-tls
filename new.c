#include <stdio.h>
#include <assert.h>

#include "evt_tls.h"

typedef struct test_tls_s {
    evt_tls_conn_t *comm;
} test_tls_t;

int test_tls_connect(test_tls_t *t)
{
    return evt_tls_connect(t->comm);
}

struct my_data {
    char data[16*1024];
    int sz;
    int stalled;
}test_data;

//test nio_handler
int test_nio_hdlr(evt_tls_conn_t *c, void *buf, int sz)
{
    //write to test data as simulation of network write
    memset(&test_data, 0, sizeof(test_data));
    memcpy(test_data.data, buf, sz);
    test_data.sz = sz;
    test_data.stalled = 0;
    return 0;
}

int processed_recv_data(test_tls_t *stream )
{
    int r = 0;
    if ( !test_data.stalled ) {
	test_data.stalled = 1;
	r = evt_tls_feed_data(stream->comm, test_data.data, test_data.sz); 
    }
    return r;
}

int evt_tls_write(evt_tls_conn_t *c, void *msg, int *str_len)
{
    return evt__ssl_op(c, EVT_TLS_OP_WRITE, msg, str_len);
}

int main()
{

    evt_ctx_t tls;
    assert(0 == evt_tls_init(&tls));


    assert(0 == evt_tls_is_crtf_set(&tls));
    assert(0 == is_key_set(&tls));
    
    if (!evt_tls_is_crtf_set(&tls)) {
	evt_tls_set_crt_key(&tls, "server-cert.pem", "server-key.pem");
    }

    assert( 1 == evt_tls_is_crtf_set(&tls));
    assert( 1 == is_key_set(&tls));


    test_tls_t *clnt_hdl = malloc(sizeof *clnt_hdl);
    assert(clnt_hdl != 0);
    evt_tls_conn_t *clnt = getSSL(&tls );
    SSL_set_connect_state(clnt->ssl);
    evt_tls_set_nio(clnt, test_nio_hdlr);

    clnt_hdl->comm = clnt;


    evt_tls_conn_t *svc = getSSL(&tls);
    SSL_set_accept_state(svc->ssl);
    test_tls_t *svc_hdl = malloc(sizeof(test_tls_t));
    assert(svc_hdl != 0);
    evt_tls_set_nio(svc, test_nio_hdlr);
    svc_hdl->comm = svc;

    test_tls_connect(clnt_hdl);
    processed_recv_data(svc_hdl);
    processed_recv_data(clnt_hdl);
    processed_recv_data(svc_hdl);
    processed_recv_data(clnt_hdl);

    char msg[] = "Hello Simulated event based tls engine\n";
    int str_len = sizeof(msg);
    int r =  evt_tls_write(clnt_hdl->comm, msg, &str_len);
    (void)r;
    
    processed_recv_data(svc_hdl);

    free(clnt_hdl);
    free(svc_hdl);
    return 0;
}
