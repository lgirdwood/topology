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
static int write_block_header(struct soc_tplg_priv *soc_tplg, u32 type,
	u32 vendor_type, u32 version, u32 index, size_t payload_size)
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
	hdr.payload_size = payload_size;
	hdr.index = index;

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
		"version %d at offset 0x%x\n", type, (long unsigned int)payload_size,
		(long int)payload_size, vendor_type, version, offset);

	soc_tplg->next_hdr_pos += hdr.payload_size + sizeof(hdr);

	bytes = write(soc_tplg->out_fd, &hdr, sizeof(hdr));
	if (bytes != sizeof(hdr)) {
		fprintf(stderr, "error: can't write section header %lu\n",
			(long unsigned int)bytes);
		return bytes;
	}

	return bytes;
}

static int write_mixer_block(struct soc_tplg_priv *soc_tplg,
	struct list_head *base, int size)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;
	int ret, wsize = 0, i;

	/* write the header for this block */
	// TODO get version, playload, etc
	ret = write_block_header(soc_tplg, 0, 0, 0, 0, size);
	if (ret < 0) {
		//tplg_error("failed to write control elems %d\n", ret);
		return ret;
	}

	/* write each mixer control from block */
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		verbose(soc_tplg, " mixer '%s': start to write %d bytes\n",
			elem->id, elem->size);
		i = write(soc_tplg->out_fd, elem->mixer_ctrl, elem->size);
		verbose(soc_tplg, " written %d bytes\n", i);
		wsize += i;
	}

	if (wsize != size)
		fprintf(stderr, "write mixer block: size mismatch %d %d\n",
			size, wsize);

	return 0;
}

static int write_graph_block(struct soc_tplg_priv *soc_tplg,
	struct list_head *base, int size)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;
	int ret, wsize = 0, i;

	/* write the header for this block */
	// TODO get version, playload, etc
	ret = write_block_header(soc_tplg, 0, 0, 0, 0, size);
	if (ret < 0) {
		//tplg_error("failed to write control elems %d\n", ret);
		return ret;
	}

	/* write each mixer control from block */
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		verbose(soc_tplg, " route '%s': start to write %d bytes\n",
			elem->id, elem->size);
		i = write(soc_tplg->out_fd, elem->route, elem->size);
		verbose(soc_tplg, " written %d bytes\n", i);
		wsize += i;
	}

	if (wsize != size)
		fprintf(stderr, "size mismatch %d %d\n", size, wsize);

	return 0;
}

static int write_widget_block(struct soc_tplg_priv *soc_tplg,
	struct list_head *base, int size)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;
	int ret, wsize = 0, i;

	/* write the header for this block */
	// TODO get version, playload, etc
	ret = write_block_header(soc_tplg, 0, 0, 0, 0, size);
	if (ret < 0) {
		//tplg_error("failed to write control elems %d\n", ret);
		return ret;
	}

	/* write each mixer control from block */
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		verbose(soc_tplg, " widget '%s': start to write %d bytes\n",
			elem->id, elem->size);
		i = write(soc_tplg->out_fd, elem->widget, elem->size);
		verbose(soc_tplg, " written %d bytes\n", i);
		wsize += i;
	}

	if (wsize != size)
		fprintf(stderr, "write widget block: size mismatch %d %d\n",
			size, wsize);

	return 0;
}

static struct soc_tplg_elem *lookup_element(struct list_head *base,
				const char* id,
				u32 type)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		if (!strcmp(elem->id, id) && elem->type == type) {
			return elem;
		}
	}

	return NULL;
}

static int calc_refelem_size(struct soc_tplg_priv *soc_tplg,
	struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *ref_elem;
	int size = 0;

	/*
	 * Currently only widget could be appended with other controls.
	 * For the widget, we should calc the ref elem's object size.
	 *
	 * File block representation for DAPM widget :-
	 * +-------------------------------------+-----+
	 * | struct snd_soc_tplg_hdr             |  1  |
	 * +-------------------------------------+-----+
	 * | struct snd_soc_tplg_dapm_widget     |  N  |
	 * +-------------------------------------+-----+
	 * |   struct snd_soc_tplg_enum_control  | 0|1 |
	 * |   struct snd_soc_tplg_mixer_control | 0|N |
	 * +-------------------------------------+-----+
	 */
	if (elem->type != PARSER_TYPE_DAPM_WIDGET)
		return 0;

	base = &elem->ref_list;
	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, struct soc_tplg_ref, list);
		if ((ref->type == PARSER_TYPE_ENUM) ||
			(ref->type == PARSER_TYPE_MIXER)) {

			ref_elem = lookup_element(&soc_tplg->control_list,
				ref->id, ref->type);
			if (ref_elem == NULL) {
				return -EINVAL;
			}

			size += ref_elem->size;
		}
	}

 	return size;
}

static int calc_block_size(struct soc_tplg_priv *soc_tplg,
	struct list_head *base)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;
	int size = 0, refelem_size;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);

		/*
		 * For the elem (e.g. widget) which references other elems,
		 * we should also calc the size of referenced elems because
		 * the referenced elem's object would be appended to the
		 * end of current elem (e.g. widget).
		 */
		refelem_size = calc_refelem_size(soc_tplg, elem);

		/*
		 * elem->size only indicates the object size (not include the 
		 * elem structure itself)
		 */
		size += elem->size + refelem_size;
	}

	return size;
}

static int write_block(struct soc_tplg_priv *soc_tplg, struct list_head *base,
	int type)
{
	int size;

	/* calculate the block size in bytes for all elems in this list */
	size = calc_block_size(soc_tplg, base);
	if (size == 0)
		return 0;

	printf("block_size for type %d is %d\n", type, size);

	/* write each elem for this block */
	/* TODO: add all objects */
	switch (type) {
	case PARSER_TYPE_MIXER:
		return write_mixer_block(soc_tplg, base, size);
	case PARSER_TYPE_BYTES:
	case PARSER_TYPE_ENUM:
	case PARSER_TYPE_DAPM_GRAPH:
		return write_graph_block(soc_tplg, base, size);
	case PARSER_TYPE_DAPM_WIDGET:
		return write_widget_block(soc_tplg, base, size);
	case PARSER_TYPE_PCM:
	default:
		return -EINVAL;
	}

	return 0;
}

int socfw_write_data(struct soc_tplg_priv *soc_tplg)
{
	int ret;

	fprintf(stdout, "writing output file\n");

	/* soc_tplg->out_fd is the handle of output file */

	/*
	 * write control elems.
	 */
	/*
	 * jinyao: the control elems which are referenced by widgets should be
	 * removed from this control_list or should have a tag to inidicate it.
	 */
	ret = write_block(soc_tplg, &soc_tplg->control_list,
		PARSER_TYPE_MIXER);
	if (ret < 0) {
		//tplg_error("failed to write control elems %d\n", ret);
		return ret;
	}
	
	/* write widget elems */
	ret = write_block(soc_tplg, &soc_tplg->widget_list,
		PARSER_TYPE_DAPM_WIDGET);
	if (ret < 0) {
		//tplg_error("failed to write widget elems %d\n", ret);
		return ret;
	}

	/* write route elems */
	ret = write_block(soc_tplg, &soc_tplg->route_list,
		PARSER_TYPE_DAPM_GRAPH);
	if (ret < 0) {
		//tplg_error("failed to write graph elems %d\n", ret);
		return ret;
	}

	/* TODO: add other items */

	/* The handle of output file is closed in socfw_free */

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

	err = write_block_header(soc_tplg, type, 0, 0, 0, size);
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

