#include "Enclave_t.h"
#include "Ocall_wrappers.h"

#include <openssl/ssl.h>

#define	INADDR_NONE		((unsigned long int) 0xffffffff)

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
	return((c & ~0x7F) == 0);
}

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
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

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		printe("socket");
		exit(EXIT_FAILURE);
	}

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	printl("Connecting...");
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
        exit(EXIT_FAILURE);
	}

	return sockfd;
}

RSA * createRSA(unsigned char * key, int pub){
    RSA *rsa= NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL){
        printf( "Failed to create key BIO");
        return 0;
    }
    if(pub){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }else{
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL){
        printf( "Failed to create RSA");
    }
 
    return rsa;
}

void cerv_decrypt(unsigned char* key, unsigned char* enc_data, int data_len, unsigned char* decrypted){
    RSA * rsa = createRSA(key,0);
    int dec_len = RSA_private_decrypt(data_len, enc_data,decrypted,rsa,padding);
    if(dec_len == -1){
        printf("DECRYPTION FAILED\n");
    }else{
        printf("DECRYPTION PASSED\n");
        printf("LENGTH %d\n", dec_len);
    }
}

void ecall_start_tls_client(const char* inter, const char* priv, const char* ip)
{
    int sock;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    sock = create_socket_client(ip, 8080);

 
    /* Send SSL certificate to the server */
    sgx_write(sock, inter, strlen(inter));
  
    char buff[4096];
    sgx_read(sock, buff, 4096); 
    char* msg = strndup(buff, 256);

    if(msg != "REJECT"){
        unsigned char decrypted[256];
        cerv_decrypt((unsigned char*) priv, (unsigned char*) msg, 256, decrypted); 
        printf("Decrypted Text =%s\n",decrypted);
    }
    printf("%s\n", msg);
    sgx_close(sock);
}
