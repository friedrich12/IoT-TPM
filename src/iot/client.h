// Copyright (c) 2021, Friedrich Doku

#ifndef CLIENT_H
#define CLIENT_H

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>

#define MAX 4096
#define SA struct sockaddr

typedef struct {
	int				   sockfd;
	int				   connfd;
	struct sockaddr_in servaddr;
	struct sockaddr_in cli;
} Client;

// 192.168.0.37 Friedy's macbook
void client_run(Client * conn, char * ipaddr, int port);

void client_send(Client * conn, char * msg, int size);

char * client_read(Client * conn);

void client_shutdown(Client * conn);

#endif
