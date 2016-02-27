/*
 * Copyright 2016 Joël Jungo, Titouan Mesot
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * SolHSM ENGINE for OpenSSL
 * @file:     solhsm_engine.c
 * @author:   Titouan Mesot
 * @contributor: Joel Jungo
 * @date:     Dec-Janv, 2014
 */
#include "solhsm_engine.h"


#define HSM_PORT 9222

/* Struct to store the load parameters, ready for IPC exchange */
struct init_parameters {
    char    solhsm_pub_cert_path[128];
    char    solhsm_priv_cert_path[128];
    char    solhsm_hsm_ip[30];
    int     solhsm_key_id;
    int     solhsm_set_debug;
};

struct init_parameters init_params;

/* Define available command for on load parameters*/

static const ENGINE_CMD_DEFN solhsm_cmd_defns[] = {
    {CMD_ZMQ_SERVER_PUB_CERT_PATH,
    "ZMQ_SERVER_PUB_CERT_PATH",
    "Specifies the path to server public certificat",
    ENGINE_CMD_FLAG_STRING},
    {CMD_ZMQ_CLIENT_PRIV_CERT_PATH,
    "ZMQ_CLIENT_PRIV_CERT_PATH",
    "Specifies the path to client private certificat",
    ENGINE_CMD_FLAG_STRING},
    {CMD_ZMQ_SERVER_IP,
    "ZMQ_SERVER_IP",
    "Specifies the HSM ip address",
    ENGINE_CMD_FLAG_STRING},
    {CMD_KEY_ID,
    "KEY_ID",
    "Specifies the key id to work with",
    ENGINE_CMD_FLAG_NUMERIC},
    {CMD_SET_DEBUG,
    "ZMQ_SET_DEBUG",
    "Specifies if we run in debug mod, set 1 to be verbose in syslog",
    ENGINE_CMD_FLAG_NUMERIC},
    {0, NULL, NULL, 0}
};

/* Struct to hook our methods to OpenSSL */

static RSA_METHOD solhsm_rsa ={
    "solhsm RSA method",
    solhsm_pub_enc,
    solhsm_pub_dec,
    solhsm_priv_enc,
    solhsm_priv_dec,
    NULL, //mod_exp
    NULL,
    NULL, //RSA_init
    NULL,
    0, 	  //RSA_FLAGS
    NULL, //App_data, Unknow in documentation .../* ?? */
    NULL,
    NULL,
    NULL,
};

/* Constants used when creating the ENGINE */
static const char *engine_solhsm_id = 	"solhsm";
static const char *engine_solhsm_name = "solHSM Engine";

static EVP_PKEY* solhsm_load_private_key(ENGINE *e, const char *key_id,
                                            UI_METHOD *ui_method,
                                            void *callback_data)
{
    /*init zmq crypto */
    zcert_t *client_cert = zcert_load (init_params.solhsm_priv_cert_path);
    zcert_t *server_cert = zcert_load (init_params.solhsm_pub_cert_path);
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE solhsm load (dummy) private key \
                        is called with hsm is = %s and key_id = %i]",
                        init_params.solhsm_hsm_ip, init_params.solhsm_key_id);

    zctx_t* solhsm_zmq_ctx = zctx_new();
    void *client = zsocket_new (solhsm_zmq_ctx, ZMQ_REQ);
    /*apply zmq crypto */
    zcert_apply (client_cert, client);
    zsocket_set_curve_serverkey (client, zcert_public_txt (server_cert));

    zsocket_connect(client, "tcp://%s:%i", init_params.solhsm_hsm_ip,HSM_PORT);

    /*Forge frame*/
    rsa_key_payload_st* rsa_key = create_rsa_key_payload(0,
                                                        init_params.solhsm_key_id,
                                                        RSA_KEY_DUMMY_PRIV,
                                                        RSA_KEY_PEM,
                                                        NULL);

    net_frame_container* c_s = create_container(1, RSA_KEY,
                                            get_rsa_key_payload_size(rsa_key));

    /*Send frame*/
    net_send(client, c_s, rsa_key);
    /*wait a response*/
    net_frame_container *c_r = malloc(sizeof(net_frame_container));

    void* ptr_key_recv = net_receive(client, c_r);

    /*process respons*/
    rsa_key_payload_st *rsa_key_rcv = (rsa_key_payload_st *)ptr_key_recv;

    /*check respons status*/
    if(rsa_key_rcv->key_type == RSA_KEY_ERROR) {
        //error in respons
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO, "[OpenSSL ENGINE solhsm load privkey rcv msg is in \
                            ERROR: %s]",rsa_key_rcv->key_data);
        return NULL;
    }
    else if(rsa_key_rcv->key_type == RSA_KEY_PUB) {
        /*wrong key type*/
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO,"[OpenSSL ENGINE solhsm load privkey rcv msg is a \
                                public key, we are waiting a dummy key]");
        return NULL;
    } else if(rsa_key_rcv->key_type == RSA_KEY_DUMMY_PRIV) {
        /*get key, and create EVP_PKEY to return*/

        /*First create a bio*/
        BIO *bio = BIO_new_mem_buf((void*)rsa_key_rcv->key_data,
                                                    rsa_key_rcv->key_data_size);

        /*get private key */
        EVP_PKEY *pkey = NULL;
        pkey = PEM_read_bio_PrivateKey(bio, NULL,NULL, NULL);

        /*free the memory*/
        free(rsa_key_rcv->key_data);
        free(rsa_key_rcv);
        zcert_destroy (&client_cert);
        zcert_destroy (&server_cert);
        zctx_destroy(&solhsm_zmq_ctx);

        /*return dummy private key */
        return pkey;
    }
    else{
    if(init_params.solhsm_set_debug)
    syslog(LOG_INFO, "[OpenSSL ENGINE solhsm load privkey failed]");
    return NULL;
    }
}

/* encrypt */
static int solhsm_pub_enc(int flen, const unsigned char *from, unsigned char *to,
                            RSA *rsa, int padding)
{
if(init_params.solhsm_set_debug)
    syslog(LOG_INFO, "[OpenSSL ENGINE solhsm encrypt is called with hsm is = %s \
                    and key_id = %i]",
                    init_params.solhsm_hsm_ip,
                    init_params.solhsm_key_id);

    /*init zmq crypto*/
    zcert_t *client_cert = zcert_load (init_params.solhsm_priv_cert_path);
    zcert_t *server_cert = zcert_load (init_params.solhsm_pub_cert_path);

    zctx_t* solhsm_zmq_ctx = zctx_new();
    void *client = zsocket_new (solhsm_zmq_ctx, ZMQ_REQ);
    /*apply zmq crypto*/
    zcert_apply (client_cert, client);
    zsocket_set_curve_serverkey (client, zcert_public_txt (server_cert));
    zsocket_connect(client, "tcp://%s:%i", init_params.solhsm_hsm_ip,HSM_PORT);


    /*forge payload to send*/
    rsa_std_payload_st* rsa_to_send = create_rsa_std_payload( flen,
                                                        init_params.solhsm_key_id,
                                                        padding,
                                                        RSA_PUB_ENC,
                                                        // cast to work with in
                                                        // frame forgery
                                                        (unsigned char*) from);
    /*forge container*/
    net_frame_container* c_to_send = create_container(1, RSA_STD,
                                        get_rsa_std_payload_size(rsa_to_send));

    /*send */
    net_send(client, c_to_send, rsa_to_send);

    /*forge container to receive*/
    net_frame_container* c_rcv = malloc(sizeof(net_frame_container));

    /*receive*/
    void* ptr_rcv = net_receive(client,c_rcv);
    /*cast*/
    rsa_std_payload_st *rsa_rcv = (rsa_std_payload_st *)ptr_rcv;

    if(rsa_rcv->operation == RSA_STD_ERROR) {
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO, "[OpenSSL ENGINE solhsm HSM reply error in pub_enc : %s]",
                            rsa_rcv->data);
        return -1;
    }

    /*give value to openssl*/
    int ret = rsa_rcv->data_length;
    memcpy(to, rsa_rcv->data, ret);
    free(rsa_rcv);
    zcert_destroy (&client_cert);
    zcert_destroy (&server_cert);
    zctx_destroy(&solhsm_zmq_ctx);

    return ret;
}

/* verify arbitrary data */
static int solhsm_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                            RSA *rsa, int padding)
{
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE solhsm verify is called with hsm is = %s and \
                            key_id = %i]",
                            init_params.solhsm_hsm_ip,
                            init_params.solhsm_key_id);

    /*init zmq crypto*/
    zcert_t *client_cert = zcert_load (init_params.solhsm_priv_cert_path);
    zcert_t *server_cert = zcert_load (init_params.solhsm_pub_cert_path);

    zctx_t* solhsm_zmq_ctx = zctx_new();
    void *client = zsocket_new (solhsm_zmq_ctx, ZMQ_REQ);
    /*apply zmq crypto*/
    zcert_apply (client_cert, client);
    zsocket_set_curve_serverkey (client, zcert_public_txt (server_cert));
    zsocket_connect(client, "tcp://%s:%i", init_params.solhsm_hsm_ip,HSM_PORT);

    /*forge payload to send*/
    rsa_std_payload_st* rsa_to_send = create_rsa_std_payload(flen,
                                                    init_params.solhsm_key_id,
                                                    padding,
                                                    RSA_PUB_DEC,
                                                    // cast to work with in frame
                                                    // forgery
                                                    (unsigned char*) from);
    /*forge container*/
    net_frame_container* c_to_send = create_container(1, RSA_STD,
                                        get_rsa_std_payload_size(rsa_to_send));

    /*send*/
    net_send(client, c_to_send, rsa_to_send);

    /*forge container to receive*/
    net_frame_container* c_rcv = malloc(sizeof(net_frame_container));

    /*receive*/
    void* ptr_rcv = net_receive(client,c_rcv);
    /*cast*/
    rsa_std_payload_st *rsa_rcv = (rsa_std_payload_st *)ptr_rcv;

    if(rsa_rcv->operation == RSA_STD_ERROR) {
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO, "[OpenSSL ENGINE solhsm HSM reply error in pub_dec : %s]",
                            rsa_rcv->data);
        return -1;
    }

    /*give value to openssl*/
    int ret = rsa_rcv->data_length;
    memcpy(to, rsa_rcv->data, ret);
    free(rsa_rcv);
    zcert_destroy (&client_cert);
    zcert_destroy (&server_cert);
    zctx_destroy(&solhsm_zmq_ctx);

    return ret;
}

/* decrypt */
static int solhsm_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE solhsm decrypt is called with hsm is = %s and \
                            key_id = %i]",
                            init_params.solhsm_hsm_ip,
                            init_params.solhsm_key_id);

    /*init zmq crypto*/
    zcert_t *client_cert = zcert_load (init_params.solhsm_priv_cert_path);
    zcert_t *server_cert = zcert_load (init_params.solhsm_pub_cert_path);

    zctx_t* solhsm_zmq_ctx = zctx_new();
    void *client = zsocket_new (solhsm_zmq_ctx, ZMQ_REQ);
    /*apply zmq crypto*/
    zcert_apply (client_cert, client);
    zsocket_set_curve_serverkey (client, zcert_public_txt (server_cert));
    zsocket_connect(client, "tcp://%s:%i", init_params.solhsm_hsm_ip,HSM_PORT);

    /*forge payload to send*/
    rsa_std_payload_st* rsa_to_send = create_rsa_std_payload( flen,
                                                        init_params.solhsm_key_id,
                                                        padding,
                                                        RSA_PRIV_DEC,
                                                        // cast to work with in
                                                        // frame forgery
                                                        (unsigned char*) from);
    /*forge container*/
    net_frame_container* c_to_send = create_container(1, RSA_STD,
                                        get_rsa_std_payload_size(rsa_to_send));

    /*send all !*/
    net_send(client, c_to_send, rsa_to_send);

    /*forge container to receive*/
    net_frame_container* c_rcv = malloc(sizeof(net_frame_container));

    /*receive*/
    void* ptr_rcv = net_receive(client,c_rcv);
    /*cast*/
    rsa_std_payload_st *rsa_rcv = (rsa_std_payload_st *)ptr_rcv;

    if(rsa_rcv->operation == RSA_STD_ERROR) {
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO, "[OpenSSL ENGINE solhsm HSM reply error in priv_dec : %s]",
                            rsa_rcv->data);
        return -1;
    }
    /*give value to openssl*/
    int ret = rsa_rcv->data_length;
    memcpy(to, rsa_rcv->data, ret);
    free(rsa_rcv);
    zcert_destroy (&client_cert);
    zcert_destroy (&server_cert);
    zctx_destroy(&solhsm_zmq_ctx);

    return ret;
}


/* sign */
static int solhsm_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE solhsm sign is called with hsm is = \
                            %s and key_id = %i]",
                            init_params.solhsm_hsm_ip,
                            init_params.solhsm_key_id);
    /*init zmq crypto*/
    zcert_t *client_cert = zcert_load (init_params.solhsm_priv_cert_path);
    zcert_t *server_cert = zcert_load (init_params.solhsm_pub_cert_path);

    zctx_t* solhsm_zmq_ctx = zctx_new();
    void *client = zsocket_new (solhsm_zmq_ctx, ZMQ_REQ);
    /*apply zmq crypto*/
    zcert_apply (client_cert, client);
    zsocket_set_curve_serverkey (client, zcert_public_txt (server_cert));
    zsocket_connect(client, "tcp://%s:%i", init_params.solhsm_hsm_ip,HSM_PORT);

    /*forge payload to send*/
    rsa_std_payload_st* rsa_to_send = create_rsa_std_payload(flen,
                                                        init_params.solhsm_key_id,
                                                        padding,
                                                        RSA_PRIV_ENC,
                                                        // cast to work with in
                                                        // frame forgery
                                                        (unsigned char*) from);
    /*forge container*/
    net_frame_container* c_to_send = create_container(1, RSA_STD,
                                        get_rsa_std_payload_size(rsa_to_send));

    /*send all !*/
    net_send(client, c_to_send, rsa_to_send);

    /*forge container to receive*/
    net_frame_container* c_rcv = malloc(sizeof(net_frame_container));

    /*receive*/
    void* ptr_rcv = net_receive(client,c_rcv);
    /*cast*/
    rsa_std_payload_st *rsa_rcv = (rsa_std_payload_st *)ptr_rcv;

    if(rsa_rcv->operation == RSA_STD_ERROR) {
        if(init_params.solhsm_set_debug)
            syslog(LOG_INFO, "[OpenSSL ENGINE solhsm HSM reply error in priv_enc : %s]",
                                rsa_rcv->data);
        return -1;
    }

    /*give value to openssl*/
    int ret = rsa_rcv->data_length;
    memcpy(to, rsa_rcv->data, ret);
    free(rsa_rcv);
    zcert_destroy (&client_cert);
    zcert_destroy (&server_cert);
    zctx_destroy(&solhsm_zmq_ctx);

    return ret;
}


/* This internal function is used by ENGINE_solhsm() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
    /*Here we hook all methods, loadprivatekey include*/
    if(!ENGINE_set_id(e, engine_solhsm_id) ||
        !ENGINE_set_name(e, engine_solhsm_name) ||
        !ENGINE_set_RSA(e, &solhsm_rsa) ||
        !ENGINE_set_destroy_function(e, solhsm_destroy) ||
        !ENGINE_set_init_function(e, solhsm_init) ||
        !ENGINE_set_finish_function(e, solhsm_finish) ||
        !ENGINE_set_cmd_defns(e, solhsm_cmd_defns) ||
        !ENGINE_set_ctrl_function(e, solhsm_ctrl)||
        !ENGINE_set_load_privkey_function(e, solhsm_load_private_key)) {
            return 0;
    }
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE loading failed]");
    return 1;
}


static ENGINE *engine_solhsm(void)
{
    ENGINE *ret = ENGINE_new();
    if(!ret)
    return NULL;
    if(!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}


void ENGINE_load_solhsm(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_solhsm();
    if(!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


/* Destructor  */
static int solhsm_destroy(ENGINE *e)
{
    /*No more global zmq context to avoid multiprocessing problem with stunnel*/
    closelog ();
    return 1;
}


/* (de)initialisation functions. */
static int solhsm_init(ENGINE *e)
{
    /*No more global zmq context to avoid multiprocessing problem with stunnel*/

    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO, "[OpenSSL ENGINE solhsm init OK]");
    return 1;
}


static int solhsm_finish(ENGINE *e)
{
    if(init_params.solhsm_set_debug)
        syslog(LOG_INFO,"[OpenSSL ENGINE solhsm finish called ]");
    closelog ();
    return 1;
}


static int solhsm_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    switch (cmd) {
        case CMD_SET_DEBUG:
            if(i == 1)
                init_params.solhsm_set_debug = 1;
            else
                init_params.solhsm_set_debug = 0;
            /*Start logging */
            if(init_params.solhsm_set_debug)
                openlog("solhsm ENGINE for OpenSSL", LOG_PID, LOG_USER);
            if(init_params.solhsm_set_debug)
                syslog(LOG_INFO, "[OpenSSL ENGINE solhsm is in debug mode]");
            return 1;
        case CMD_ZMQ_SERVER_PUB_CERT_PATH:
            strncpy(init_params.solhsm_pub_cert_path, p,
            sizeof(init_params.solhsm_pub_cert_path));
            if(init_params.solhsm_set_debug)
                syslog(LOG_INFO, "[OpenSSL ENGINE solhsm command public cert \
                                    path is set to %s]", (const char *)p);
            return 1;
        case CMD_ZMQ_CLIENT_PRIV_CERT_PATH:
            strncpy(init_params.solhsm_priv_cert_path, p,
            sizeof(init_params.solhsm_priv_cert_path));
            if(init_params.solhsm_set_debug)
                syslog(LOG_INFO, "[OpenSSL ENGINE solhsm command private cert \
            p                   ath is set to %s]", (const char *)p);
            return 1;
        case CMD_ZMQ_SERVER_IP:
            strncpy(init_params.solhsm_hsm_ip , p,
            sizeof(init_params.solhsm_hsm_ip ));
            if(init_params.solhsm_set_debug)
                syslog(LOG_INFO, "[OpenSSL ENGINE solhsm command hsm ip is set \
                                to %s]", (const char *)p);
            return 1;
        case CMD_KEY_ID:
            init_params.solhsm_key_id = (int)i;
            if(init_params.solhsm_set_debug)
                syslog(LOG_INFO, "[OpenSSL ENGINE solhsm command key id is set to %i]",
                                (int)i);
            return 1;
        default:
        break;
    }
    return 0;
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_fn(ENGINE *e, const char *id)
{
    if(id && (strcmp(id, engine_solhsm_id) != 0))
        return 0;
    if(!bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
