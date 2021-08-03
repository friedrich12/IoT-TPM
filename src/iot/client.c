// Copyright (c) 2021, Friedrich Doku

#include "client.h"

// 192.168.0.37 Friedy's macbook
void client_run(Client * conn, char * ipaddr, int port)
{
	// socket create and varification
	conn->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (conn->sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	} else {
		printf("Socket successfully created..\n");
	}

	bzero(&conn->servaddr, sizeof(conn->servaddr));

	// assign IP, PORT
	conn->servaddr.sin_family	   = AF_INET;
	conn->servaddr.sin_addr.s_addr = inet_addr(ipaddr);
	conn->servaddr.sin_port		   = htons(port);

	// connect the client socket to server socket
	if (connect(conn->sockfd, (SA *)&conn->servaddr, sizeof(conn->servaddr)) != 0) {
		printf("Client with the server failed...\n");
		exit(0);
	} else {
		printf("connected to the server..\n");
	}
}

void client_send(Client * conn, char * msg, int size)
{
	write(conn->sockfd, msg, size);
}

char * client_read(Client * conn)
{
	char buff[MAX];
	read(conn->sockfd, buff, MAX);
	return strdup(buff);
}

void client_shutdown(Client * conn)
{
	close(conn->sockfd);
	printf("Client closed");
}
