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

#ifndef UTIL_H
#define UTIL_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <openssl/aes.h>

/* To get images from the camera*/
#include "cam.h"

/* To create a server for key exchange */
#include "server.h"

/* To communicate with the sever*/
#include "client.h"


struct runner {
	Client		cli;
	ImageGetter imget;
	uint8_t *	key;
	char *		camera;
	char *		ip;
};

typedef struct runner runner;


#endif
