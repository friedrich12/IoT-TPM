/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef BUF_H
#define BUF_H

#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#ifdef __cplusplus
extern "C" {
#endif
#define X509_L_BUF_LOAD 1
#define X509_LOOKUP_load_buf(x, name, type) \
	X509_LOOKUP_ctrl((x), X509_L_BUF_LOAD, (name), (long)(type), NULL)

#ifdef __cplusplus
}
#endif


struct x509_lookup_method_st {
	char * name;
	int (*new_item)(X509_LOOKUP * ctx);
	void (*free)(X509_LOOKUP * ctx);
	int (*init)(X509_LOOKUP * ctx);
	int (*shutdown)(X509_LOOKUP * ctx);
	int (*ctrl)(X509_LOOKUP * ctx, int cmd, const char * argc, long argl, char ** ret);
	int (*get_by_subject)(X509_LOOKUP * ctx, X509_LOOKUP_TYPE type, X509_NAME * name, X509_OBJECT * ret);
	int (*get_by_issuer_serial)(X509_LOOKUP * ctx, X509_LOOKUP_TYPE type, X509_NAME * name, ASN1_INTEGER * serial, X509_OBJECT * ret);
	int (*get_by_fingerprint)(X509_LOOKUP * ctx, X509_LOOKUP_TYPE type, const unsigned char * bytes, int len, X509_OBJECT * ret);
	int (*get_by_alias)(X509_LOOKUP * ctx, X509_LOOKUP_TYPE type, const char * str, int len, X509_OBJECT * ret);
};

/* This is the functions plus an instance of the local variables. */
struct x509_lookup_st {
	int					 init;		  /* have we been started */
	int					 skip;		  /* don't use us. */
	X509_LOOKUP_METHOD * method;	  /* the functions */
	void *				 method_data; /* method data */
	X509_STORE *		 store_ctx;	  /* who owns us */
};

X509_LOOKUP_METHOD * X509_LOOKUP_buffer();

int by_buffer_ctrl(X509_LOOKUP * ctx, int cmd, const char * argp, long argl, char * ret);

int X509_load_cert_buf(X509_LOOKUP * ctx, const char * certBuf, int type);

int X509_load_crl_buf(X509_LOOKUP * ctx, const char * certBuf, int type);

int X509_load_cert_crl_buf(X509_LOOKUP * ctx, const char * certBuf, int type);

extern X509_LOOKUP_METHOD x509_buffer_lookup;

#endif
