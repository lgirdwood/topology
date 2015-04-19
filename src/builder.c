/*
  Copyright(c) 2014-2015 Intel Corporation
  All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

*/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "socfw.h"

#include <dirent.h>
#include <alsa/asoundef.h>
#include <alsa/version.h>
#include <alsa/global.h>
#include <alsa/input.h>
#include <alsa/output.h>
#include <alsa/error.h>
#include <alsa/conf.h>
/* TODO: no longer need list.h after integrating it into alsa lib */
#include "list.h"

#include "topology.h"

static void verbose(struct soc_tplg_priv *soc_tplg, const char *fmt, ...)
{
	int offset = lseek(soc_tplg->out_fd, 0, SEEK_CUR);
	va_list va;

	va_start(va, fmt);
	if (soc_tplg->verbose) {
		fprintf(stdout, "0x%x/%d -", offset, offset);
		vfprintf(stdout, fmt, va);
	}
	va_end(va);
}

/* write out block header to output file */
static int write_header(struct soc_tplg_priv *soc_tplg, u32 type,
	u32 vendor_type, u32 version, u32 id, size_t size)
{
	struct snd_soc_tplg_hdr hdr;
	size_t bytes;
	int offset = lseek(soc_tplg->out_fd, 0, SEEK_CUR);

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = SND_SOC_TPLG_MAGIC;
	hdr.abi = SND_SOC_TPLG_ABI_VERSION;
	hdr.type = type;
	hdr.vendor_type = vendor_type;
	hdr.version = version;
	hdr.size = size;
	hdr.id = id;

	/* make sure file offset is aligned with the calculated HDR offset */
	if (offset != soc_tplg->next_hdr_pos) {
		fprintf(stderr, "error: New header is at offset 0x%x but file"
			" offset 0x%x is %s by %d bytes\n",
			soc_tplg->next_hdr_pos, offset,
			offset > soc_tplg->next_hdr_pos ? "ahead" : "behind",
			abs(offset - soc_tplg->next_hdr_pos));
		exit(-EINVAL);
	}

	fprintf(stdout, "New header type %d size 0x%lx/%ld vendor %d "
		"version %d at offset 0x%x\n", type, (long unsigned int)size,
		(long int)size, vendor_type, version, offset);

	soc_tplg->next_hdr_pos += hdr.size + sizeof(hdr);

	bytes = write(soc_tplg->out_fd, &hdr, sizeof(hdr));
	if (bytes != sizeof(hdr)) {
		fprintf(stderr, "error: can't write section header %lu\n",
			(long unsigned int)bytes);
		return bytes;
	}

	return 0;
}

int socfw_import_vendor(struct soc_tplg_priv *soc_tplg, const char *name,
	int type)
{
	size_t bytes, size;
	char buf[CHUNK_SIZE];
	int i, chunks, rem, err;

	soc_tplg->vendor_fd = open(name, O_RDONLY);
	if (soc_tplg->vendor_fd < 0) {
		fprintf(stderr, "error: can't open %s %d\n",
			name, soc_tplg->vendor_fd);
		return soc_tplg->vendor_fd;
	}


	size = lseek(soc_tplg->vendor_fd, 0, SEEK_END);
	if (size <= 0)
		return size;

	verbose(soc_tplg, " vendor: file size is %d bytes\n", size);

	err = write_header(soc_tplg, type, 0, 0, 0, size);
	if (err < 0)
		return err;

	lseek(soc_tplg->vendor_fd, 0, SEEK_SET);

	chunks = size / CHUNK_SIZE;
	rem = size % CHUNK_SIZE;

	for (i = 0; i < chunks; i++) {
		bytes = read(soc_tplg->vendor_fd, buf, CHUNK_SIZE);
		if (bytes < 0 || bytes != CHUNK_SIZE) {
			fprintf(stderr, "error: can't read vendor data %lu\n",
				(long unsigned int)bytes);
			return bytes;
		}

		bytes = write(soc_tplg->out_fd, buf, CHUNK_SIZE);
		if (bytes < 0 || bytes != CHUNK_SIZE) {
			fprintf(stderr, "error: can't write vendor data %lu\n",
				(long unsigned int)bytes);
			return bytes;
		}
	}

	bytes = read(soc_tplg->vendor_fd, buf, rem);
	if (bytes < 0 || bytes != rem) {
		fprintf(stderr, "error: can't read vendor data %lu\n",
			(long unsigned int)bytes);
		return bytes;
	}

	bytes = write(soc_tplg->out_fd, buf, rem);
	if (bytes < 0 || bytes != rem) {
		fprintf(stderr, "error: can't write vendor data %lu\n", (long unsigned int)bytes);
		return bytes;
	}

	return 0;
}

