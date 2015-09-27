/*    Copyright (C) 2014  Joël Jungo, Titouan Mesot
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <czmq.h>
#include <stdio.h>
#include <string.h>

/*
 * _Last modification_ :    17.10.14
 * _Author_ :               J.Jungo
 * _Contributors_ :         T.Mesot
 *
 * This code a small proof of concept of CurveZQM. This part is designed for
 * genrate a certificates (pub and priv) with Curve25519
 *
 * Keys are generate on 256bits (strong as 3096bits RSA).
 * 
 * gcc -o generate_cert generate_cert.c -lczmq -lsodium  -Wall -Wextra
 */

#define DEFAULT_CERT_NAME   "mycert"


int main (int argc, char * argv[]){
    char file_name[127];

    zcert_t *cert = zcert_new();

    zcert_set_meta(cert, "name", "My certificate");
    if (argc <2){
        strcpy(file_name , DEFAULT_CERT_NAME);
        printf("Generate cert: %s.cert %s.cert_secret\n", DEFAULT_CERT_NAME, 
                                               DEFAULT_CERT_NAME);    }
    else{
        strcpy(file_name, argv[1]);
        printf("Generate cert: %s.cert %s.cert_secret\n", file_name, file_name);
    }
    strcat(file_name, ".cert");

    zcert_save(cert, file_name);

    zcert_destroy(&cert);

    return 0;
}
