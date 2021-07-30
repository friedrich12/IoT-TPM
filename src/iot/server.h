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

#ifndef SERVER_H
#define SERVER_H

#include "cert.h"
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX 4096
#define SA struct sockaddr

typedef struct {
	int				   sockfd;
	int				   connfd;
	struct sockaddr_in servaddr;
	struct sockaddr_in cli;
	CertV			   cerv;
} Server;


/* Reads a cert from the client */
char * get_cert(int sockfd);

void server_init(Server * server, int port);

void server_run(Server * server, char * cert_file_path);

void server_shutdown(Server * server);

#endif
