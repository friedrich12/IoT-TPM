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


#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Utilites */
#include "util.h"


/* Print key as hexstr */
static void
phex(uint8_t * str)
{
	uint8_t len = 16;

	unsigned char i;
	for (i = 0; i < len; ++i) {
		printf("%.2x", str[i]);
	}
	printf("\n");
}


/* Convert string hex to array for AES KEY */
uint8_t *
process_key(const char * hexstr)
{
	size_t	  len		= strlen(hexstr);
	size_t	  final_len = len / 2;
	uint8_t * chrs		= (uint8_t *)malloc((final_len + 1) * sizeof(*chrs));
	for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
		chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
	chrs[final_len] = '\0';
	return chrs;
}

/* TODO: Load keys from configuration file
 * Example config:
 * key=dataforkey
 * camera=/dev/video0
 * ip=192.168.0.37
 */
void load_config(FILE * file, runner * src)
{
	char name[128];
	char val[128];

	while (fscanf(file, "%127[^=]=%127[^\n]%*c", name, val) == 2) {
		if (0 == strcmp(name, "camera")) {
			src->camera = strdup(val);
		} else if (0 == strcmp(name, "key")) {
			src->key = process_key(strdup(val));
		} else if (0 == strcmp(name, "ip")) {
			src->ip = strdup(val);
		} else {
			printf("Invalid configuration option: %s", name);
			exit(1);
		}
	}
}

char * aes_encrypt(unsigned char * key, unsigned char * in, size_t in_size)
{
	AES_KEY		  ekey;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char enc_out[in_size];

	memset(iv, 0x00, AES_BLOCK_SIZE);
	AES_set_encrypt_key(key, sizeof(key) * 8, &ekey);
	AES_cbc_encrypt(in, enc_out, in_size, &ekey, iv, AES_ENCRYPT);

	return strdup((char *)enc_out);
}

int main(int argc, char * argv[])
{
	runner src;

	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	printf("IoT-TPM\n");

	if (argc < 2) {
		printf("INVALID ARGUMENTS Usage: iottpm root.crt\n");
		exit(EXIT_FAILURE);
	}


	FILE * fp = fopen("config", "r");
	if (fp < 0) {
		printf("FAILED TO OPEN FILE. DID YOU CREATE /config?\n");
		exit(1);
	}

	load_config(fp, &src);

	/* VERIFY THE USER */
	Server s;
	server_init(&s, 8080);
	server_run(&s, argv[1], src.key);
	server_shutdown(&s);


	/* GRAB CAMEREA FRAME */
	initialize_imget(&src.imget, src.camera);
	set_img_format(&src.imget);
	setup_buffers(&src.imget);
	grab_frame(&src.imget);

	/* ENCRYPT THE IMAGE */
	int	   size = src.imget.bufferinfo.bytesused;
	char * eimg = aes_encrypt(src.key, src.imget.buffer, size);


	/* SEND IMAGE TO CLOUD */
	client_run(&src.cli, src.ip, 8080);
	client_send(&src.cli, eimg, size);
	client_shutdown(&src.cli);

	return 0;
}
