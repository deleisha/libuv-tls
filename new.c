#include <stdio.h>
#include <assert.h>

#include "evt_tls.h"

typedef struct test_tls_s {
    //our connection, it can be server or client
    //evt_tls_conn_t *ccn;
    //evt_tls_conn_t *peer;
    //comm[0] - ccn and comm[1] - peer
    evt_tls_conn_t comm[2];
} test_tls_t;

int test_tls_connect(test_tls_t *t)
{
    return evt_tls_connect(&t->comm[0]);
}

struct my_data {
    char data[16*1024];
    int sz;
}test_data;

//test nio_handler
int test_nio_hdlr(evt_tls_conn_t *c, void *buf, int sz)
{
    test_tls_t *t = (test_tls_t*)c;
    //write to test data as simulation of network write
    memset(&test_data, 0, sizeof(test_data));
    memcpy(test_data.data, buf, sz);
    test_data.sz = sz;
    return 0;
}



int processed_recv_data(test_tls_t *stream )
{
    return evt_tls_feed_data(stream, test_data.data,test_data.sz); 
}

int main()
{

    evt_tls_t tls;
    assert(0 == evt_tls_init(&tls));


    assert(0 == evt_tls_is_crtf_set(&tls));
    assert(0 == is_key_set(&tls));
    
    if (!evt_tls_is_crtf_set(&tls)) {
	evt_tls_set_crt_key(&tls, "server-cert.pem", "server-key.pem");
    }

    assert( 1 == evt_tls_is_crtf_set(&tls));
    assert( 1 == is_key_set(&tls));


    test_tls_t *tls_strm = malloc(sizeof *tls_strm);
    evt_tls_conn_t *cn = malloc(sizeof *cn);
    evt_tls_conn_t *clnt = getSSL(&tls, cn);
    SSL_set_connect_state(clnt->ssl);
    tls_strm->comm[0] = *clnt;

    evt_tls_conn_t *s = malloc(sizeof *s);
    evt_tls_conn_t *svc = getSSL(&tls, s);
    SSL_set_accept_state(svc->ssl);
    tls_strm->comm[1] = *svc;



    test_tls_connect(tls_strm);
    //simulate_nio(clnt, svc);
    //simulate_nio(svc, clnt);
    processed_recv_data(svc);
    processed_recv_data(clnt);
    processed_recv_data(svc);
    processed_recv_data(clnt);


    char msg[] = "Hello Simulated event based tls engine\n";
    int r = SSL_write(svc->ssl, msg, sizeof(msg));
    (void)r;
    simulate_nio(svc, clnt);

    free(cn);
    free(s);
    return 0;
}
