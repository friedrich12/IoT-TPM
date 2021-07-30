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

#ifndef CAM_H
#define CAM_H


#include <stdio.h>
#include <stdlib.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/v4l2-common.h>
#include <linux/v4l2-controls.h>
#include <linux/videodev2.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>


typedef struct {
	int						   fd;			   // File descriptor
	struct v4l2_format		   imageFormat;	   // Image Format
	struct v4l2_requestbuffers requestBuffer;
	struct v4l2_buffer		   queryBuffer;
	struct v4l2_buffer		   bufferinfo;
	char *					   buffer;
} ImageGetter;

void initialize_imget(ImageGetter * g, char * device);

void set_img_format(ImageGetter * g);

void setup_buffers(ImageGetter * g);

int grab_frame(ImageGetter * g);

#endif
