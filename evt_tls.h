#ifndef EVT_TLS_H
#define EVT_TLS_H

#include <uv.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "queue.h"



typedef struct evt_tls_conn_t {
    BIO     *app_bio_; //Our BIO, All IO should be through this
    SSL     *ssl;
    BIO     *ssl_bio_; //the ssl BIO used only by openSSL

    int (*meta_hdlr)(struct evt_tls_conn_t *c, void *edata, int len);

    QUEUE q;
  //  uv_work_t wrk;

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

    //flag to signify if ssl error has occured
    int ssl_err_;

    void *live_con[2];
} evt_tls_t;


//supported TLS operation
enum tls_op_type {
    EVT_TLS_OP_HANDSHAKE
   ,EVT_TLS_OP_READ
   ,EVT_TLS_OP_WRITE
   ,EVT_TLS_OP_SHUTDOWN
};

evt_tls_conn_t *getSSL(evt_tls_t *d_eng);
int evt_tls_set_crt_key(evt_tls_t *tls, char *crtf, char *key);
int evt_tls_init(evt_tls_t *tls);
int evt_tls_is_crtf_set(evt_tls_t *t);
int is_key_set(evt_tls_t *t);
int evt_tls_feed_data(evt_tls_conn_t *c, void *data, int sz);
int after__wrk(evt_tls_conn_t *c, void *buf);
int simulate_nio(evt_tls_conn_t *src, evt_tls_conn_t *dest);
int evt__ssl_op(evt_tls_conn_t *c, enum tls_op_type op, void *buf, int *sz);
int evt_tls_connect(evt_tls_conn_t *con /*, is callback reqd*/);
void evt_tls_set_nio(evt_tls_conn_t *c, int (*fn)(evt_tls_conn_t *t, void *data, int sz));
#endif //define EVT_TLS_H
