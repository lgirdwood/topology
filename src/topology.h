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
#include <dirent.h>
#include <limits.h>

#include <linux/types.h>
#include <sound/asound.h>
#include <uapi/sound/asoc.h>
#include <uapi/sound/tlv.h>

#include <alsa/asoundef.h>
#include <alsa/version.h>
#include <alsa/global.h>
#include <alsa/input.h>
#include <alsa/output.h>
#include <alsa/error.h>
#include <alsa/conf.h>
/* TODO: no longer need list.h after integrating it into alsa lib */
#include "list.h"

/* kernel typedefs */
typedef	uint32_t u32;
typedef	int32_t s32;
typedef	uint16_t u16;
typedef	int16_t s16;
typedef	uint8_t u8;
typedef	int8_t s8;

struct soc_tplg_ref;
struct soc_tplg_elem;

/* internal topology type not used by kernel */
enum parser_type {
	PARSER_TYPE_TLV = 0,
	PARSER_TYPE_MIXER,
	PARSER_TYPE_ENUM,
	PARSER_TYPE_TEXT,
	PARSER_TYPE_DATA,
	PARSER_TYPE_BYTES,
	PARSER_TYPE_STREAM_CONFIG,
	PARSER_TYPE_STREAM_CAPS,
	PARSER_TYPE_PCM,
	PARSER_TYPE_DAPM_WIDGET,
	PARSER_TYPE_DAPM_GRAPH,
	PARSER_TYPE_BE,
	PARSER_TYPE_CC,
};

#define CHUNK_SIZE 	4096
#define TLV_DB_SCALE_SIZE (sizeof(u32) * 3)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct soc_tplg_priv {

	/* opaque vendor data */
	int vendor_fd;
	char *vendor_name;

	/* out file */
	int out_fd;

	int verbose;
	u32 version;

	/* runtime state */
	u32 next_hdr_pos;
	int index;

	/* list of each element type */
	struct list_head tlv_list;
	struct list_head widget_list;
	struct list_head pcm_list;
	struct list_head be_list;
	struct list_head cc_list;
	struct list_head route_list;
	struct list_head text_list;
	struct list_head pdata_list;
	struct list_head pcm_config_list;
	struct list_head pcm_caps_list;

	/* type-specific control lists */
	struct list_head mixer_list;
	struct list_head enum_list;
	struct list_head bytes_ext_list;
};

/* object text references */
struct soc_tplg_ref {
	u32 type;
	struct soc_tplg_elem *elem;
	char id[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
	struct list_head list;
};

struct soc_tplg_elem {

	char id[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];

	/* storage for textsand data if this is text or data elem*/
	char texts[SND_SOC_TPLG_NUM_TEXTS][SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
	
	int index;
	enum parser_type type;

	int size; /* total size of this object inc pdata and ref objects */

	/* UAPI object for this elem */
	union {
		void *obj;
		struct snd_soc_tplg_mixer_control *mixer_ctrl;
		struct snd_soc_tplg_enum_control *enum_ctrl;
		struct snd_soc_tplg_bytes_control *bytes_ext;
		struct snd_soc_tplg_dapm_widget *widget;
		struct snd_soc_tplg_pcm_dai *pcm;
		struct snd_soc_tplg_pcm_dai *be;
		struct snd_soc_tplg_pcm_dai *cc;
		struct snd_soc_tplg_dapm_graph_elem *route;
		struct snd_soc_tplg_stream_config *stream_cfg;
		struct snd_soc_tplg_stream_caps *stream_caps;

		/* these do not map to UAPI structs but are internal only */
		struct snd_soc_tplg_ctl_tlv *tlv;
		struct snd_soc_tplg_private *data;
	};

	/* an element may refer to other elements:
	 * a mixer control may refer to a tlv,
	 * a widget may refer to a mixer control array,
	 * a graph may refer to some widgets.
	 */
	struct list_head ref_list;
	struct list_head list; /* list of all elements with same type */
};

int socfw_write_data(struct soc_tplg_priv *soc_tplg);
void tplg_error(const char *fmt, ...);

#define SOC_TPLG_DEBUG
#ifdef SOC_TPLG_DEBUG
#define tplg_dbg tplg_error
#else
#define tplg_dbg(fmt, arg...) do { } while (0)
#endif

