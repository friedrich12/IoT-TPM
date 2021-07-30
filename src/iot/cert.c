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

#include "cert.h"

int padding = RSA_PKCS1_PADDING;

static X509 *
load_cert(const char * certBuf)
{
	X509 * x	= NULL;
	BIO *  cert = NULL;

	if ((cert = BIO_new(BIO_s_mem())) == NULL) {
		goto end;
	}

	BIO_write(cert, certBuf, strlen(certBuf));

	x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
end:
	if (cert != NULL) {
		BIO_free(cert);
	}

	return x;
}

static int
check(X509_STORE * ctx, const char * certBuf)
{
	X509 *			 x = NULL;
	int				 i = 0, ret = 0;
	X509_STORE_CTX * csc = NULL;

	x = load_cert(certBuf);
	if (x == NULL) {
		goto end;
	}

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		goto end;
	}

	X509_STORE_set_flags(ctx, 0);
	if (!X509_STORE_CTX_init(csc, ctx, x, 0)) {
		goto end;
	}
	////// See crypto/asn1/t_x509.c for ideas on how to access and print the values
	//printf("X.509 name: %s\n", x->name);
	i = X509_verify_cert(csc);
	X509_STORE_CTX_free(csc);

	ret = 0;
end:
	ret = (i > 0);
	if (x != NULL) {
		X509_free(x);
	}

	return ret;
}

int validateKey(const char * rsaKeyCA, const char * rsaCertificate)
{
	int			  ret	   = 0;
	X509_STORE *  cert_ctx = NULL;
	X509_LOOKUP * lookup   = NULL;

	cert_ctx = X509_STORE_new();
	if (cert_ctx == NULL) {
		goto end;
	}

	OpenSSL_add_all_algorithms();

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_buffer());
	if (lookup == NULL) {
		goto end;
	}

	if (!X509_LOOKUP_load_buf(lookup, rsaKeyCA, X509_FILETYPE_PEM)) {
		goto end;
	}

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
	if (lookup == NULL) {
		goto end;
	}

	X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

	ret = check(cert_ctx, rsaCertificate);
end:
	if (cert_ctx != NULL) {
		X509_STORE_free(cert_ctx);
	}

	return ret;
}


void cert_info(const char * cert_pem)
{
	BIO * b = BIO_new(BIO_s_mem());
	BIO_puts(b, cert_pem);
	X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	//Subject
	BIO_printf(bio_out, "Subject: ");
	X509_NAME_print(bio_out, X509_get_subject_name(x509), 0);
	BIO_printf(bio_out, "\n");

	//Issuer
	BIO_printf(bio_out, "Issuer: ");
	X509_NAME_print(bio_out, X509_get_issuer_name(x509), 0);
	BIO_printf(bio_out, "\n");

	//Public Key
	EVP_PKEY * pkey = X509_get_pubkey(x509);
	EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);

	//Signature
	//X509_signature_print(bio_out, X509_get0_tbs_sigalg(x509)->algorithm, X509_get0_tbs_sigalg(x509));
	//BIO_printf(bio_out,"\n");

	BIO_free(bio_out);
	BIO_free(b);
	X509_free(x509);
}

RSA * createRSA(unsigned char * key, int pub)
{
	RSA * rsa	 = NULL;
	BIO * keybio = NULL;
	keybio		 = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		printf("Failed to create key BIO");
		return 0;
	}
	if (pub) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL) {
		printf("Failed to create RSA");
	}

	return rsa;
}

void cerv_encrypt(const char * cert_pem, unsigned char * data, int data_len, unsigned char * encrypted)
{
	EVP_PKEY * pubkey = NULL;
	RSA *	   rsa	  = NULL;

	BIO * b = BIO_new(BIO_s_mem());
	BIO_puts(b, cert_pem);
	X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	//Public Key
	pubkey = X509_get_pubkey(x509);

	rsa = EVP_PKEY_get1_RSA(pubkey);

	int enc_len = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	if (enc_len == -1) {
		printf("ENCRYPTION FAILED\n");
	} else {
		printf("ENCRYPTION PASSED\n");
		printf("LENGTH %d\n", enc_len);
	}

	EVP_PKEY_free(pubkey);
}

void cerv_decrypt(unsigned char * key, unsigned char * enc_data, int data_len, unsigned char * decrypted)
{
	RSA * rsa	  = createRSA(key, 0);
	int	  dec_len = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	if (dec_len == -1) {
		printf("DECRYPTION FAILED\n");
	} else {
		printf("DECRYPTION PASSED\n");
		printf("LENGTH %d\n", dec_len);
	}
}

char *
load_file(char const * path)
{
	char * buffer = 0;
	long   length;
	FILE * f = fopen(path, "r");

	if (f) {
		fseek(f, 0, SEEK_END);
		length = ftell(f);
		fseek(f, 0, SEEK_SET);
		buffer = (char *)malloc((length + 1) * sizeof(char));
		if (buffer) {
			fread(buffer, sizeof(char), length, f);
		}
		fclose(f);
	}

	buffer[length] = '\0';
	return buffer;
}

void cerv_init(CertV * certv, char * cert_path, char * inter_data)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	certv->cert	 = load_file(cert_path);
	certv->inter = inter_data;
}

void cerv_info(CertV * cerv)
{
	cert_info(cerv->cert);
	cert_info(cerv->inter);
}

int cerv_validate(CertV * certv)
{
	int ret = validateKey(certv->cert, certv->inter);

	if (ret == 1) {
		printf("VERIFICATION PASSED!\nb");
	} else {
		printf("UNABLE TO VERIFY INTERMIDIATE CERT\n");
	}

	return ret;
}
