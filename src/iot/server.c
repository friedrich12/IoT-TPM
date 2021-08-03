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

#include "server.h"


/* Reads a cert from the client */
char * get_cert(int sockfd)
{
	printf("Reading Certificate into byte array\n");
	char data[MAX];

	int nb = read(sockfd, data, MAX);
	printf("READ %d bytes", nb);

	return strdup(data);
}

void server_init(Server * server, int port)
{
	/* Create a socket */
	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server->sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	} else {
		printf("Socket successfully created..\n");
	}
	bzero(&server->servaddr, sizeof(server->servaddr));

	/* Assign a port */
	server->servaddr.sin_family		 = AF_INET;
	server->servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server->servaddr.sin_port		 = htons(port);

	/* Bind */
	if ((bind(server->sockfd, (SA *)&server->servaddr, sizeof(server->servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	} else {
		printf("Socket successfully binded..\n");
	}
}

void server_run(Server * server, char * cert_file_path, char * aes_key)
{
	/* Listen for connection */
	if ((listen(server->sockfd, 5)) != 0) {
		printf("Listen failed...\n");
		exit(0);
	} else {
		printf("Server listening..\n");
	}

	/* Accept the connection */
	size_t len	   = sizeof(server->cli);
	server->connfd = accept(server->sockfd, (SA *)&server->cli, &len);
	if (server->connfd < 0) {
		printf("server acccept failed...\n");
		exit(0);
	} else {
		printf("server acccept the client...\n");
	}

	char * inter_data = get_cert(server->connfd);

	cerv_init(&server->cerv, cert_file_path, inter_data);
	int rez = cerv_validate(&server->cerv);
	if (rez) {
		/* Encrypt key using cert and send to client */
		char text[256];
		for (int i = 0; i < 17; i++) {
			text[i] = aes_key[i];
		}
		unsigned char encrypted[256];
		cerv_encrypt(inter_data, text, strlen(text), encrypted);
		send(server->connfd, encrypted, 256, 0);
	} else {
		/* Tell them they didn't make the cut */
		char * no = "REJECT";
		send(server->connfd, no, strlen(no), 0);
	}
}

void server_shutdown(Server * server)
{
	close(server->sockfd);
	printf("Server shudown");
}
