#include <assert.h>
#include "evt_tls.h"

static void tls_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}


evt_tls_conn_t *getSSL(evt_tls_t *d_eng, evt_tls_conn_t *c)
{
     //d_eng->ctn->ssl  = SSL_new(d_eng->ctx);
     SSL *ssl  = SSL_new(d_eng->ctx);

     if ( ssl ) {
	 c->ssl = ssl;
     }

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
    tls->ssl_err_ = 0;

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

    //if handshake is not complete, do it again
    if (!SSL_is_init_finished(c->ssl)) {
	rv = evt__ssl_op(c, EVT_TLS_OP_HANDSHAKE, NULL, NULL);
    }
    else {
	char txt[4096] = {0};
	rv = SSL_read(c->ssl, txt, sizeof(txt));
	printf("%s", txt);
    }
    return rv;
}

int after__wrk(evt_tls_conn_t *c, void *buf)
{
    int pending = BIO_pending(c->app_bio_);
    if ( !(pending > 0) )
	return 0;

    int p = BIO_read(c->app_bio_, buf, pending);
    assert(p == pending);
    return p;
}

int simulate_nio(evt_tls_conn_t *src, evt_tls_conn_t *dest)
{

    char buf[16*1024] = {0}; //default size
    int p = after__wrk(src,  buf);
    evt_tls_feed_data(dest, buf, p);
    return 0;
}

int evt__ssl_op(evt_tls_conn_t *c, enum tls_op_type op, void *buf, int *sz)
{
    int r = 0;
    int bytes = 0;
    char tbuf[16*1024] = {0};
    switch ( op ) {
	case EVT_TLS_OP_HANDSHAKE:
	r = SSL_do_handshake(c->ssl);
	if ( r < 0 ) {
	   bytes = after__wrk(c, tbuf);
	   if ( c->meta_hdlr)
	       c->meta_hdlr(c, tbuf, bytes);
	}
	break;

        case EVT_TLS_OP_READ:
        r = SSL_read(c->ssl, buf, *sz);
	if ( r < 0 ) {
            bytes = after__wrk(c, tbuf);
            if ( c->meta_hdlr)
                c->meta_hdlr(c, tbuf, bytes);
        }
	break;

	case EVT_TLS_OP_WRITE:
	r = SSL_write(c->ssl, buf, *sz);
	if ( r < 0 )
	    bytes = after__wrk(c, tbuf);
	break;

	case EVT_TLS_OP_SHUTDOWN:
	r = SSL_shutdown(c->ssl);
	if ( r < 0 )
	    bytes = after__wrk(c, tbuf);
	break;

	default:
	assert( 0 && "Unsupported operation");
	break;
    }
    return r;
}

int evt_tls_connect(evt_tls_conn_t *con /*, is callback reqd*/)
{
    int r = evt__ssl_op(con, EVT_TLS_OP_HANDSHAKE, NULL, NULL);
    return r;
}

int evt_close();
int evt_force_close();
//cleaN up calls