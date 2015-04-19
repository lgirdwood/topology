/*
  Copyright(c) 2014-2015 Intel Corporation
  Copyright(c) 2010-2011 Texas Instruments Incorporated,
  All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
  The full GNU General Public License is included in this distribution
  in the file called LICENSE.GPL.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "socfw.h"

struct soc_tplg_priv;

struct soc_tplg_priv *socfw_new(const char *name, int verbose);
void socfw_free(struct soc_tplg_priv *soc_tplg);
int socfw_import_vendor(struct soc_tplg_priv *soc_tplg, const char *name, int type);
int parse_conf(struct soc_tplg_priv *soc_tplg, const char *filename);

static void usage(char *name)
{
	fprintf(stdout, "usage: %s conf outfile [options]\n\n", name);

	fprintf(stdout, "Add vendor firmware text	[-vfw firmware]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct soc_tplg_priv *soc_tplg;
	int i;
	
	if (argc < 4)
		usage(argv[0]);

	soc_tplg = socfw_new(argv[2], 1);
	if (soc_tplg < 0) {
		fprintf(stderr, "failed to open %s\n", argv[argc - 1]);
		exit(0);
	}

	for (i = 2 ; i < argc - 1; i++) {

		/* vendor options */
		if (!strcmp("-vfw", argv[i])) {
			if (++i == argc)
				usage(argv[0]);

			socfw_import_vendor(soc_tplg, argv[i], SND_SOC_TPLG_VENDOR_FW);
			continue;
		}
	}

	parse_conf(soc_tplg, argv[1]);

	socfw_free(soc_tplg);
	return 0;
}

