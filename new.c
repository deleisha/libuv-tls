#include <stdio.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>


typedef struct evt_tls_conn_t {
    BIO     *app_bio_; //Our BIO, All IO should be through this
    SSL     *ssl;
    BIO     *ssl_bio_; //the ssl BIO used only by openSSL
    //my Queue
} evt_tls_conn_t;


typedef struct evt_tls_s
{
    //tls connection XXX make this a queue
    evt_tls_conn_t *ctn;

    //find better place for it , should be one time init
    SSL_CTX *ctx;

    //flags which tells if cert is set
    int cert_set;

    //flags which tells if key is set
    int key_set;
} evt_tls_t;

static void tls_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

//int evt_close();
//int evt_force_close();

evt_tls_conn_t *getSSL(evt_tls_t *d_eng, evt_tls_conn_t *c)
{
     //d_eng->ctn->ssl  = SSL_new(d_eng->ctx);
     c->ssl  = SSL_new(d_eng->ctx);

     //create new bio pair
     //use default buf size for now.
     BIO_new_bio_pair(&(c->ssl_bio_), 0, &(c->app_bio_), 0);

     SSL_set_bio(c->ssl, c->ssl_bio_, c->ssl_bio_);

     d_eng->ctn = c;

     return d_eng->ctn;
}


#define CERTFILE "server-cert.pem"
#define KEYFILE "server-key.pem"
int evt_tls_set_crt_key(evt_tls_t *tls, char *crtf, char *key)
{
    //SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, uv__tls_verify_peer);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);

    int r = SSL_CTX_use_certificate_file(tls->ctx, CERTFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        return -1;
    }
    tls->cert_set = 1;

    r = SSL_CTX_use_PrivateKey_file(tls->ctx, KEYFILE, SSL_FILETYPE_PEM);
    if(r != 1) {
        return -1;
    }

    r = SSL_CTX_check_private_key(tls->ctx);
    if(r != 1) {
        return -1;
    }
    tls->key_set = 1;
    return 0;
}


int evt_tls_init(evt_tls_t *tls)
{
    tls_begin();

    //Currently we support only TLS, No DTLS
    tls->ctx = SSL_CTX_new(SSLv23_method());
    if(!tls->ctx) {
        return ENOMEM;
    }
    
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    SSL_CTX_set_options(tls->ctx, options);

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY |
         SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER       |
         SSL_MODE_ENABLE_PARTIAL_WRITE             |
         SSL_MODE_RELEASE_BUFFERS
    );

    tls->cert_set = 0;
    tls->key_set = 0;

    return 0;
}

int evt_tls_is_crtf_set(evt_tls_t *t)
{
    return t->cert_set && t->key_set;
}

int is_key_set(evt_tls_t *t)
{
    return t->key_set;
}


int evt_tls_feed_data(evt_tls_conn_t *c, void *data, int sz)
{
    int rv =  BIO_write(c->app_bio_, data, sz);
    assert( rv == sz);

    //if handshake is not complete
    if (!SSL_is_init_finished(c->ssl)) {
	int rv = SSL_do_handshake(c->ssl);
    }
    else {
	char txt[4096] = {0};
	int r = SSL_read(c->ssl, txt, sizeof(txt));
	printf("%s", txt);
    }
}

int simulate_nio(evt_tls_conn_t *src, evt_tls_conn_t *dest)
{
    char buf[4096*2] = {0};
    int pending  = BIO_pending(src->app_bio_);
    int p = BIO_read(src->app_bio_, buf, pending);
    assert( p == pending);

    evt_tls_feed_data(dest, buf, p);
}

int evt__ssl_op(enum ssl_op_type op, void *buf, int sz)
{
    int r = 0;
    switch ( op ) {

	SSL_OP_HANDSHAKE:
	r = SSL_do_handshake(c->ssl);
	if ( r < 0 )
	    goto handle_error;
	break;

	SSL_OP_READ:
	r = SSL_read(c->ssl, buf, sz);
	if ( r < 0 )
	    goto handle_error;
	break;

	SSL_OP_WRITE:
	r = SSL_write(c->ssl, buf, sz);
	if ( r < 0 )
	    goto handle_error;
	break;

	SSL_OP_SHUTDOWN:
	r = SSL_shutdown(c->ssl);
	break;

	default:
	break;
    }

    handle_error:
}

int evt_tls_connect(evt_tls_conn_t *con /*, is callback reqd*/)
{
    int r = SSL_connect(con->ssl);
}

int evt_tls_accept(evt_tls_conn_t *server, evt_tls_conn_t *clnt)
{
    //SSL_accept();
}

int evt_close();
int evt_force_close();

int main()
{
    evt_tls_t tls;
    evt_tls_init(&tls);

    assert(0 == evt_tls_is_crtf_set(&tls));
    assert(0 == is_key_set(&tls));
    
    if (!evt_tls_is_crtf_set(&tls)) {
	evt_tls_set_crt_key(&tls, "server-cert.pem", "server-key.pem");
    }

    assert( 1 == evt_tls_is_crtf_set(&tls));
    assert( 1 == is_key_set(&tls));


    evt_tls_conn_t *cn = malloc(sizeof *cn);
    evt_tls_conn_t *clnt = getSSL(&tls, cn);
    SSL_set_connect_state(clnt->ssl);

    evt_tls_conn_t *s = malloc(sizeof *s);
    evt_tls_conn_t *svc = getSSL(&tls, s);
    SSL_set_accept_state(svc->ssl);


    evt_tls_connect(clnt);
    simulate_nio(clnt, svc);
    simulate_nio(svc, clnt);
    simulate_nio(clnt, svc);
    simulate_nio(svc, clnt);
    simulate_nio(clnt, svc);
    simulate_nio(svc, clnt);

    char msg[] = "Hello Simulated event based tls engine\n";
    int r = SSL_write(svc->ssl, msg, sizeof(msg));
    simulate_nio(svc, clnt);

    free(cn);
    free(s);
    return 0;
}
