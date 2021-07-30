/*
 * Copyright (C) 2021 Friedrich Doku
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CERT_H
#define CERT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "buf.h"

typedef struct {
	char * cert;
	char * inter;
} CertV;


extern int padding;

static X509 * load_cert(const char * certBuf);

static int check(X509_STORE * ctx, const char * certBuf);

int validateKey(const char * rsaKeyCA, const char * rsaCertificate);

void cert_info(const char * cert_pem);

RSA * createRSA(unsigned char * key, int pub);

void cerv_encrypt(const char * cert_pem, unsigned char * data, int data_len, unsigned char * encrypted);

void cerv_decrypt(unsigned char * key, unsigned char * enc_data, int data_len, unsigned char * decrypted);

char * load_file(char const * path);

void cerv_init(CertV * certv, char * cert_path, char * inter_data);

void cerv_info(CertV * cerv);

int cerv_validate(CertV * certv);

#endif
