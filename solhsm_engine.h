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
 * solHSM OPENSSL ENGINE header file.
 * @file:     solhsm_engine.h
 * @author:   Mesot Titouan
 * @date:     Dec 30, 2014
 * @Version:  0.1
 */


#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <czmq.h>
#include "./lib/solhsm_network.h"

/* ENGINE on load parameters*/
#define CMD_ZMQ_SERVER_PUB_CERT_PATH	ENGINE_CMD_BASE
#define CMD_ZMQ_CLIENT_PRIV_CERT_PATH	(ENGINE_CMD_BASE+1)
#define CMD_ZMQ_SERVER_IP				(ENGINE_CMD_BASE+2)
#define CMD_KEY_ID						(ENGINE_CMD_BASE+3)
#define CMD_SET_DEBUG					(ENGINE_CMD_BASE+4)

/**
 * Method to destroy the engine
 * @param ENGINE to detroy
 * @return 1 if ok, 0 else other
 */
static int solhsm_destroy(ENGINE *e);
/**
 * Method to initialize the engine
 * @param ENGINE to init
 * @return 1 if ok, 0 else other
 */
static int solhsm_init(ENGINE *e);
/**
 * Method call on finish using the engine
 * @param ENGINE to finish
 * @return 1 if ok, 0 else other
 */
static int solhsm_finish(ENGINE *e);
/**
 * Method to send parameters to the engine, is call by OpenSSL on start
 * Every parameters is passed in a while to this function
 * @param e engine
 * @param cmd command name
 * @param i value of argument if is numeric
 * @param p value of argument if is a string
 * @param f not tested/documented in OpenSSL, call back function(as parameter ?)
 * @return 1 if ok, 0 else other
 */
static int solhsm_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

/**
 * Method to ask for rsa public encryption, is call by OpenSSL on request
 * @param flen size of data in from
 * @param from data before processing
 * @param to data after processing
 * @param rsa rsa struct contains dummy key, and others stuff provided by OpenSSL
 * @param padding padding type
 * @return size of data in to
 */
 
 
static int solhsm_pub_enc(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding);
  
  
/**
 * Method to ask for rsa public decryption, is call by OpenSSL on request
 * @param flen size of data in from
 * @param from data before processing
 * @param to data after processing
 * @param rsa rsa struct contains dummy key, and others stuff provided by OpenSSL
 * @param padding padding type
 * @return size of data in to
 */

static int solhsm_pub_dec(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding);
  
  
/**
 * Method to ask for rsa private encryption, is call by OpenSSL on request
 * @param flen size of data in from
 * @param from data before processing
 * @param to data after processing
 * @param rsa rsa struct contains dummy key, and others stuff provided by OpenSSL
 * @param padding padding type
 * @return size of data in to
 */

static int solhsm_priv_enc(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding);
  
  
/**
 * Method to ask for rsa private decryption, is call by OpenSSL on request
 * @param flen size of data in from
 * @param from data before processing
 * @param to data after processing
 * @param rsa rsa struct contains dummy key, and others stuff provided by OpenSSL
 * @param padding padding type
 * @return size of data in to
 */

static int solhsm_priv_dec(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding); 
  
  
/**
 * Method to ask the load of the private key. Is call by stunnel, 
 * and others services, we avoid this to give a dummy key on call of this function
 * @param e Engine to use for this call
 * @param key_id Key it to request on HSM
 * @param ui_method Not used / not documented
 * @param callback_data Not used / not documented
 * @return EVP_PKEY sould contain the private key, but in this engine, only contains a dummy key
 */


static EVP_PKEY* solhsm_load_private_key(ENGINE *e, const char *key_id,
     UI_METHOD *ui_method, void *callback_data);
