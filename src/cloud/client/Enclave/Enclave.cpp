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

#include "Enclave_t.h"
#include "Ocall_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>

#define INADDR_NONE ((unsigned long int)0xffffffff)

int padding = RSA_PKCS1_PADDING;

static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
	EVP_cleanup();
}

static int
isascii(int c)
{
	return ((c & ~0x7F) == 0);
}

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char * cp, struct in_addr * addr)
{
	u_long val, base, n;
	char   c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val	 = 0;
		base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) +
					  (c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {
		case 1: /* a -- 32 bits */
			break;

		case 2: /* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3: /* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4: /* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char * cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char * ip, uint32_t port)
{
	int				   sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printe("socket");
		exit(EXIT_FAILURE);
	}

	dest_addr.sin_family	  = AF_INET;
	dest_addr.sin_port		  = htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	printl("Connecting...");
	if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
		exit(EXIT_FAILURE);
	}

	return sockfd;
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

void aes_decrypt(unsigned char * key, unsigned char * dec_out, unsigned char * enc_in, size_t in_size)
{
	AES_KEY		  dec_key;
	unsigned char iv[AES_BLOCK_SIZE];

	memset(iv, 0x00, AES_BLOCK_SIZE);
	AES_set_decrypt_key(key, sizeof(key) * 8, &dec_key);
	AES_cbc_encrypt(enc_in, dec_out, in_size, &dec_key, iv, AES_DECRYPT);
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

char * concat(const char * str1, const char * str2)
{
	char * result;
	snprintf(result, strlen(str1) + strlen(str2), "%s%s", str1, str2);
	return result;
}

void ecall_start_tls_client(const char * inter, const char * priv, const char * iot_ip, const char * serverip, char * filedata)
{

	int sock, sock1;

	printf("OPENSSL Version = %s\n", SSLeay_version(SSLEAY_VERSION));
	sock = create_socket_client(iot_ip, 8080);


	/* Send SSL certificate to the server */
	sgx_write(sock, inter, strlen(inter));

	unsigned char decrypted[256];
	char		  buff[4096];
	sgx_read(sock, buff, 4096);
	char * msg = strndup(buff, 256);

	if (msg != "REJECT") {
		cerv_decrypt((unsigned char *)priv, (unsigned char *)msg, 256, decrypted);
		printf("Decrypted Text =%s\n", decrypted);
	} else {
		printf("CERTIFICATE REJECTED\n");
		exit(EXIT_FAILURE);
	}
	sgx_close(sock);

	char * key = strndup((char *)decrypted, strlen(msg));
	printf("%s\n", msg);


	sock1 = create_socket_client(serverip, 8080);

	char * str = "photo1.jpg";
	sgx_write(sock1, str, strlen(str));

	int	   n;
	char   buffer[1024];
	char * rez = NULL;

	while (1) {
		n = sgx_read(sock1, buffer, 1024);
		if (n <= 0) {
			break;
		}

		rez = concat(rez, strndup(buffer, strlen(buffer)));
		bzero(buffer, 1024);
	}

	unsigned char dec_out[strlen(rez)];
	aes_decrypt((unsigned char *)key, dec_out, (unsigned char *)rez, strlen(rez));

	filedata = strndup((char *)dec_out, strlen(rez));
}
