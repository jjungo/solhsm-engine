/* <@LICENSE>
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </@LICENSE>
 */
/**
 * Library provides a small interface to use the solhsm network protocol
 * @file:     solhsm_network.h
 * @author:   Titouan Mesot
 * @date:     Dec 30, 2014
 * @Version:  0.1
 */

#pragma once
#ifndef SOLHSM_NETWORK_H
#define SOLHSM_NETWORK_H

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>
#include <zmq.h>
#include <czmq.h>

/*declaration of type of payload*/
#define	RSA_STD      0	/**< payload is RSA enc/dec/sign/verify */
#define RSA_MOD_EXP	 1	/**< payload is RSA_mod_exp */
#define	RSA_KEY		 2	/**< payload is an RSA Key */

/*declaration of operation in rsa_std payload */
#define RSA_STD_ERROR 	 0	/**< Error happend in communication*/
#define	RSA_PRIV_ENC     1	/**< call private encrypt on data on HSM*/
#define RSA_PRIV_DEC	 2  /**< call private decrypt on data on HSM */
#define RSA_PUB_ENC		 3  /**< call public encrypt on data on HSM */
#define RSA_PUB_DEC 	 4	/**< call public deencrypt on data on HSM */


/*declaration of key type in rsa_key payload */
#define	RSA_KEY_ERROR 	     0	/**< RSA Public key*/
#define	RSA_KEY_PUB  	     1	/**< RSA Public key*/
#define RSA_KEY_DUMMY_PRIV	 2  /**< RSA Dummy private key */

/*declaration of key format in rsa_key payload */
#define	RSA_KEY_PEM  	     0	/**< RSA Public key*/


/* Container struct */
 typedef struct  __attribute__((__packed__)) {
	uint8_t version; 
	uint8_t payload_type;
	uint16_t payload_size; 
} solhsm_network_frame_container ;

/* RSA Standart struct */
 typedef struct  __attribute__((__packed__)) {
	uint16_t data_length;
	uint16_t key_id;
	uint8_t  padding;
	uint8_t  operation;
	unsigned char *data;
} solhsm_rsa_std_payload ; 

/* Key struct */
 typedef struct  __attribute__((__packed__)) {
	uint16_t key_data_size;
	uint16_t key_id;
	uint8_t  key_type;
	uint8_t  key_format;
	unsigned char *key_data;
} solhsm_rsa_key_payload ; 

/**
 * Method to send a container with a payload over the zmq socket
 * Note : container and payload are free by this method after call
 * @param socket the zmq socket to use
 * @param container the filled container
 * @param payload the filled payload, type must match with the container declared type
 * @return -1 if error, 0 if succeed
 */
 
extern int solhsm_network_send(void* socket, solhsm_network_frame_container* container, void* payload);

/**
 * Method to receive a container with a payload over the zmq socket
 * Note : After use, you have to free the container and the payload
 * @param socket the zmq socket to use
 * @param container an emtpy container, will be filled by this method
 * @return a void pointer that contain the receive payload, must be cast as the type defined by the receive container
 */

extern void* solhsm_network_receive(void* socket, solhsm_network_frame_container* container);


/**
 * Method to forge a standart rsa payload
 * @param data_length the size of data field
 * @param key_id the key id to use on the HSM
 * @param padding the padding type, used with OpenSSL constant
 * @param operation the operation to do against the data field
 * @param data a pointer to the data to use on HSM, or the data processed by the HSM
 * @return a filled solhsm_rsa_std_payload struct
 */
extern solhsm_rsa_std_payload* solhsm_forge_rsa_std_payload(int data_length, int key_id, int padding, int operation, unsigned char *data); 

/**
 * Method to forge a rsa key payload
 * @param key_data_size size of key_data field, can be null on request
 * @param key_id the key id to get on the HSM
 * @param key_type the key type to get 
 * @param key_format the key format
 * @param key_data the key data, can be null on request
 * @return a filled solhsm_rsa_key_payload struct
 */

extern solhsm_rsa_key_payload* solhsm_forge_rsa_key_payload(int key_data_size, int key_id, int key_type, int key_format, unsigned char *key_data); 

/**
 * Method to forge a container
 * @param version version of the protocol
 * @param payload_type type of payload
 * @param payload_size size of payload
 * @return a filled solhsm_network_frame_container struct
 */


extern solhsm_network_frame_container* solhsm_forge_container(int version, int payload_type, int payload_size); 


/**
 * Method get the rsa payload size, should be use to fill the payload size in container frame
 * @param solhsm_rsa_std_payload the struct to compute size
 * @return size of the struct on the network (concatened without pointer)
 */
 
extern int solhsm_get_rsa_std_payload_size(solhsm_rsa_std_payload* rsa_std_payload); 

/**
 * Method get the rsa key payload size, should be use to fill the payload size in container frame
 * @param rsa_key_payload the struct to compute size
 * @return size of the struct on the network (concatened without pointer)
 */
extern int solhsm_get_rsa_key_payload_size(solhsm_rsa_key_payload* rsa_key_payload); 

#endif
