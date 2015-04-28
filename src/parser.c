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

struct map_elem {
	const char *name;
	int id;
};

static const struct map_elem widget_map[] = {
	{"input", SND_SOC_TPLG_DAPM_INPUT},
	{"output", SND_SOC_TPLG_DAPM_OUTPUT},
	{"mux", SND_SOC_TPLG_DAPM_MUX},
	{"mixer", SND_SOC_TPLG_DAPM_MIXER},
	{"pga", SND_SOC_TPLG_DAPM_PGA},
	{"out_drv", SND_SOC_TPLG_DAPM_OUT_DRV},
	{"adc", SND_SOC_TPLG_DAPM_ADC},
	{"dac", SND_SOC_TPLG_DAPM_DAC},
	{"switch", SND_SOC_TPLG_DAPM_SWITCH},
	{"pre", SND_SOC_TPLG_DAPM_PRE},
	{"post", SND_SOC_TPLG_DAPM_POST},
	{"aif_in", SND_SOC_TPLG_DAPM_AIF_IN},
	{"aif_out", SND_SOC_TPLG_DAPM_AIF_OUT},
	{"dai_in", SND_SOC_TPLG_DAPM_DAI_IN},
	{"dai_out", SND_SOC_TPLG_DAPM_DAI_OUT},
	{"dai_link", SND_SOC_TPLG_DAPM_DAI_LINK},
};

static const struct map_elem channel_map[] = {
	{"mono", SNDRV_CHMAP_MONO},	/* mono stream */
	{"fl", SNDRV_CHMAP_FL},		/* front left */
	{"fr", SNDRV_CHMAP_FR},		/* front right */
	{"rl", SNDRV_CHMAP_RL},		/* rear left */
	{"rr", SNDRV_CHMAP_RR},		/* rear right */
	{"fc", SNDRV_CHMAP_FC},		/* front center */
	{"lfe", SNDRV_CHMAP_LFE},	/* LFE */
	{"sl", SNDRV_CHMAP_SL},		/* side left */
	{"sr", SNDRV_CHMAP_SR},		/* side right */
	{"rc", SNDRV_CHMAP_RC},		/* rear center */
	{"flc", SNDRV_CHMAP_FLC},	/* front left center */
	{"frc", SNDRV_CHMAP_FRC},	/* front right center */
	{"rlc", SNDRV_CHMAP_RLC},	/* rear left center */
	{"rrc", SNDRV_CHMAP_RRC},	/* rear right center */
	{"flw", SNDRV_CHMAP_FLW},	/* front left wide */
	{"frw", SNDRV_CHMAP_FRW},	/* front right wide */
	{"flh", SNDRV_CHMAP_FLH},	/* front left high */
	{"fch", SNDRV_CHMAP_FCH},	/* front center high */
	{"frh", SNDRV_CHMAP_FRH},	/* front right high */
	{"tc", SNDRV_CHMAP_TC},		/* top center */
	{"tfl", SNDRV_CHMAP_TFL},	/* top front left */
	{"tfr", SNDRV_CHMAP_TFR},	/* top front right */
	{"tfc", SNDRV_CHMAP_TFC},	/* top front center */
	{"trl", SNDRV_CHMAP_TRL},	/* top rear left */
	{"trr", SNDRV_CHMAP_TRR},	/* top rear right */
	{"trc", SNDRV_CHMAP_TRC},	/* top rear center */
	{"tflc", SNDRV_CHMAP_TFLC},	/* top front left center */
	{"tfrc", SNDRV_CHMAP_TFRC},	/* top front right center */
	{"tsl", SNDRV_CHMAP_TSL},	/* top side left */
	{"tsr", SNDRV_CHMAP_TSR},	/* top side right */
	{"llfe", SNDRV_CHMAP_LLFE},	/* left LFE */
	{"rlfe", SNDRV_CHMAP_RLFE},	/* right LFE */
	{"bc", SNDRV_CHMAP_BC},		/* bottom center */
	{"blc", SNDRV_CHMAP_BLC},	/* bottom left center */
	{"brc", SNDRV_CHMAP_BRC},	/* bottom right center */
};

static void tplg_error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stdout, fmt, va);
	va_end(va);
}

static inline int add_ref(soc_tplg_elem_t *elem, const char* ref_id)
{
	soc_tplg_ref_t *ref;

	ref = calloc(1, sizeof(*ref));
	if (!ref)
		return -ENOMEM;

	strncpy(ref->id, ref_id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	list_add_tail(&ref->list, &elem->ref_list);
	return 0;
}

static void free_ref_list(struct list_head *base)
{
	struct list_head *pos, *npos;
	soc_tplg_ref_t *ref;

	list_for_each_safe(pos, npos, base) {
		ref = list_entry(pos, soc_tplg_ref_t, list);
		printf("\tfree ref %s\n", ref->id);
		list_del(&ref->list);
		free(ref);
	}
}

static soc_tplg_elem_t *elem_new(void)
{
	soc_tplg_elem_t *elem;

	elem = calloc(1, sizeof(*elem));
	if (!elem)
		return NULL;

	INIT_LIST_HEAD(&elem->ref_list);
	return elem;
}

static void elem_free(soc_tplg_elem_t *elem)
{
	printf("free element %s\n", elem->id);
	free_ref_list(&elem->ref_list);
	free(elem);
}

static void free_elem_list(struct list_head *base)
{
	struct list_head *pos, *npos;
	soc_tplg_elem_t *elem;

	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, soc_tplg_elem_t, list);
		list_del(&elem->list);
		elem_free(elem);
	}
}

struct soc_tplg_priv *socfw_new(const char *name, int verbose)
{
	struct soc_tplg_priv * soc_tplg;
	int fd;

	soc_tplg = calloc(1, sizeof(struct soc_tplg_priv));
	if (!soc_tplg)
		return NULL;

	/* delete any old files */
	unlink(name);

	soc_tplg->verbose = verbose;
	fd = open(name, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s err %d\n", name, -errno);
		free(soc_tplg);
		return NULL;
	}

	soc_tplg->out_fd = fd;

	INIT_LIST_HEAD(&soc_tplg->tlv_list);
	INIT_LIST_HEAD(&soc_tplg->control_list);
	INIT_LIST_HEAD(&soc_tplg->widget_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_list);
	INIT_LIST_HEAD(&soc_tplg->be_list);
	INIT_LIST_HEAD(&soc_tplg->cc_list);
	INIT_LIST_HEAD(&soc_tplg->route_list);
	INIT_LIST_HEAD(&soc_tplg->mixer_array_list);

	return soc_tplg;
}

void socfw_free(struct soc_tplg_priv *soc_tplg)
{
	close(soc_tplg->out_fd);

	free_elem_list(&soc_tplg->tlv_list);
	free_elem_list(&soc_tplg->control_list);
	free_elem_list(&soc_tplg->widget_list);
	free_elem_list(&soc_tplg->pcm_list);
	free_elem_list(&soc_tplg->be_list);
	free_elem_list(&soc_tplg->cc_list);
	free_elem_list(&soc_tplg->route_list);
	free_elem_list(&soc_tplg->mixer_array_list);

	free(soc_tplg);
}

static soc_tplg_elem_t *lookup_element(struct list_head *base,
				const char* id,
				u32 type)
{
	struct list_head *pos, *npos;
	soc_tplg_elem_t *elem;

	//printf("lookup %s, type %d\n",id, type);
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, soc_tplg_elem_t, list);
		//printf("\tfound elem '%s', type %d\n", elem->id, elem->type);
		if (!strcmp(elem->id, id) && elem->type == type) {
			return elem;
		}
	}

	return NULL;
}

static soc_tplg_elem_t *lookup_pcm_dai_stream(struct list_head *base, const char* id)
{
	struct list_head *pos, *npos;
	soc_tplg_elem_t *elem;
	struct snd_soc_tplg_pcm_dai *pcm_dai;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, soc_tplg_elem_t, list);
		if (elem->type != SND_SOC_TPLG_PCM)
			return NULL;

		pcm_dai = elem->pcm;
		//printf("\tfound pcm_dai '%s': playback '%s', capture '%s'\n", elem->id, pcm_dai->playback_caps.stream_name, pcm_dai->capture_caps.stream_name);
		if (pcm_dai && (!strcmp(pcm_dai->caps[0].name, id)
			|| !strcmp(pcm_dai->caps[1].name, id)))
			return elem;
	}

	return NULL;
}

static int lookup_widget(const char *w)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(widget_map); i++) {
		if (strcmp(widget_map[i].name, w) == 0)
			return widget_map[i].id;
	}

	return -EINVAL;
}

#if 0
static int lookup_channel(const char *c)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(channel_map); i++) {
		if (strcmp(channel_map[i].name, c) == 0)
			return channel_map[i].id;
	}

	return -EINVAL;
}
#endif

/*
 * Parse compound
 */
static int parse_compound(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	  int (*fcn)(struct soc_tplg_priv *, snd_config_t *))
{
	const char *id;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err;

	if (snd_config_get_id(cfg, &id) < 0)
		return -EINVAL;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("compound type expected for %s", id);
		return -EINVAL;
	}

	tplg_dbg("parsing compound %s\n", id);

	/* parse compound */
	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);

		if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
			tplg_error("compound type expected for %s, is %d",
				id, snd_config_get_type(cfg));
			return -EINVAL;
		}

		err = fcn(soc_tplg, n);
		if (err < 0)
			return err;
	}

	return 0;
}

/* Parse Private Data.
 *
 * Object private data
 *
 * SectionData."data name" {
 * 
 *		DataFile <filename>
 *	}
 */
static int parse_data(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	list_add_tail(&elem->list, &soc_tplg->tlv_list);

	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	elem->type = SND_SOC_TPLG_TLV;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "DataFile") == 0) {
			// TODO: get thedata
			continue;
		}
	}

	return err;
}

/* Parse Private Data.
 *
 * Object private data
 *
 * SectionText."text name" {
 * 
 *		Values [
 *			
 * 		]
 *	}
 */
static int parse_text(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	list_add_tail(&elem->list, &soc_tplg->tlv_list);

	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	elem->type = SND_SOC_TPLG_TLV;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "Values") == 0) {
			// TODO: get thedata
			continue;
		}
	}

	return err;
}

// TODO: rework the sizes here so we can parse them
#define TLV_DB_SCALE_SIZE (sizeof(unsigned int)*3)
#define MAX_TLV_DB_SCALE_STR_SIZE 256

/*
 * Parse TLV of DBScale type.
 *
 * Parse DBScale describing min, step, mute in DB.
 *
 * DBScale [
 *		min <int>
 *		step <int>
 * 		mute <int>
 * ]
 */
static int parse_tlv_dbscale(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct snd_soc_tplg_ctl_tlv *tplg_tlv;
	const char *key = NULL, *value = NULL;
	int idx = 0;

	tplg_dbg(" TLV DBScale: %s\n", elem->id);

	tplg_tlv = calloc(1, sizeof(*tplg_tlv) + TLV_DB_SCALE_SIZE);
	if (!tplg_tlv)
		return -ENOMEM;

	elem->tlv = tplg_tlv;
	tplg_tlv->numid = SNDRV_CTL_TLVT_DB_SCALE;
	tplg_tlv->size = TLV_DB_SCALE_SIZE;

	snd_config_for_each(i, next, cfg) {
		idx ^= 1;

		n = snd_config_iterator_entry(i);

		/* get key */
		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		tplg_dbg("\t%s = %s\n", key, value);

		/* get TLV data */
		if (strcmp(key, "min") == 0)
			tplg_tlv->data[0] = atoi(value);
		else if (strcmp(key, "step") == 0)
			tplg_tlv->data[1] = atoi(value);
		else if (strcmp(key, "mute") == 0)
			tplg_tlv->data[2] = atoi(value);
		else
			tplg_error("unknown key %s\n", key);
	}

	return 0;
}

/* Parse TLV.
 *
 * Each TLV is described in new section
 * Supported TLV types: DBScale.
 *
 * SectionTLV."tlv name" {
 * 		Comment "optional comments"
 *
 *		TlvType [
 *
 * 		]
 *	}
 */
static int parse_tlv(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	list_add_tail(&elem->list, &soc_tplg->tlv_list);

	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	elem->type = SND_SOC_TPLG_TLV;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "DBScale") == 0) {
			err = parse_tlv_dbscale(soc_tplg, n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse verb enable sequence");
				return err;
			}
			continue;
		}
	}

	return err;
}

#if 0
/* Parse a channel.
 *
 * Channel."channel_map.name" {
 *			reg "0"	(register)
 *			shift "0" (shift)
 * }
 */
static int parse_channel(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
#if 0
	if (strcmp(key, "reg") == 0)
		mc->reg = mc->rreg = atoi(val);
	else if (strcmp(key, "shift") == 0)
		mc->shift = mc->rshift = atoi(val);
#endif
	return 0;
}
#endif

/* Parse a Mixer Control.
 *
 * A control section has only one mixer.
 * No support for private data.
 *
 *	Mixer [
 *		Channel."channel" {
			}
 *		max
 *		invert
 *		ops
 *		tlv_array
 * 	]
 */
static int parse_mixer(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_mixer_control *mc;

	tplg_dbg("Control Mixer: %s\n", elem->id);
	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for control mixer definition");
		return -EINVAL;
	}

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -ENOMEM;
	elem->mixer_ctrl = mc;
	elem->type = SND_SOC_TPLG_MIXER;

	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	mc->hdr.index = SOC_CONTROL_IO_EXT |
		SOC_CONTROL_ID(1, 1, 0);
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | SNDRV_CTL_ELEM_ACCESS_READWRITE;
	/* TODO: mc->hdr.tlv_size, need to get tlv info */
	mc->priv.size  = 0;

	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for sequence command");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if (snd_config_get_string(n, &val) < 0) {
			tplg_error("Mixer %s: invalid %s definition\n", elem->id, key);
			return -EINVAL;
		}
		tplg_dbg("\t%s: %s\n",key, val);
#if 0
		// channel
		else if (strcmp(key, "max") == 0)
			mc->max = mc->platform_max = atoi(val);
		else if (strcmp(key, "invert") == 0)
			mc->invert = atoi(val);
		else if (strcmp(key, "tlv_array") == 0) {
			if(val[0]) {
				err = add_ref(elem, val);
				if (err < 0)
					return err;
			}
		}
#endif
	}

	return 0;
}

/* Parse a Mixer Control.
 *
 * A control section has only one mixer.
 * No support for private data.
 *
 *	Mixer [
 *		reg  (or reg_left and reg_right)
 *		shift	(or shift_left and shift_right)
 *		max
 *		invert
 *		get
 *		put
 *		tlv_array
 * 	]
 */
static int parse_enum(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_mixer_control *mc;

	tplg_dbg("Control Mixer: %s\n", elem->id);
	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for control mixer definition");
		return -EINVAL;
	}

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -ENOMEM;
	elem->mixer_ctrl = mc;
	elem->type = SND_SOC_TPLG_MIXER;

	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	mc->hdr.index = SOC_CONTROL_IO_EXT |
		SOC_CONTROL_ID(1, 1, 0);
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | SNDRV_CTL_ELEM_ACCESS_READWRITE;
	/* TODO: mc->hdr.tlv_size, need to get tlv info */
	mc->priv.size  = 0;

	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for sequence command");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if(snd_config_get_string(n, &val) < 0) {
			tplg_error("Mixer %s: invalid %s definition\n", elem->id, key);
			return -EINVAL;
		}
		tplg_dbg("\t%s: %s\n",key, val);
#if 0
		if (strcmp(key, "reg") == 0)
			mc->reg = mc->rreg = atoi(val);
		else if (strcmp(key, "reg_left") == 0)
			mc->reg = atoi(val);
		else if (strcmp(key, "reg_right") == 0)
			mc->rreg = atoi(val);
		else if (strcmp(key, "shift") == 0)
			mc->shift = mc->rshift = atoi(val);
		else if (strcmp(key, "shift_left") == 0)
			mc->shift = atoi(val);
		else if (strcmp(key, "shift_right") == 0)
			mc->rshift = atoi(val);
		else if (strcmp(key, "max") == 0)
			mc->max = mc->platform_max = atoi(val);
		else if (strcmp(key, "invert") == 0)
			mc->invert = atoi(val);
		else if (strcmp(key, "tlv_array") == 0) {
			if(val[0]) {
				err = add_ref(elem, val);
				if (err < 0)
					return err;
			}
		}
#endif
	}

	return 0;
}

/* Parse a Mixer Control.
 *
 * A control section has only one mixer.
 * No support for private data.
 *
 *	Mixer [
 *		reg  (or reg_left and reg_right)
 *		shift	(or shift_left and shift_right)
 *		max
 *		invert
 *		get
 *		put
 *		tlv_array
 * 	]
 */
static int parse_bytes(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_mixer_control *mc;

	tplg_dbg("Control Bytes: %s\n", elem->id);

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for control mixer definition");
		return -EINVAL;
	}

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -ENOMEM;
	elem->mixer_ctrl = mc;
	elem->type = SND_SOC_TPLG_MIXER;

	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	mc->hdr.index = SOC_CONTROL_IO_EXT |
		SOC_CONTROL_ID(1, 1, 0);
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | SNDRV_CTL_ELEM_ACCESS_READWRITE;
	/* TODO: mc->hdr.tlv_size, need to get tlv info */
	mc->priv.size  = 0;

	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for sequence command");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if(snd_config_get_string(n, &val) < 0) {
			tplg_error("Mixer %s: invalid %s definition\n", elem->id, key);
			return -EINVAL;
		}
		tplg_dbg("\t%s: %s\n",key, val);
#if 0
		if (strcmp(key, "reg") == 0)
			mc->reg = mc->rreg = atoi(val);
		else if (strcmp(key, "reg_left") == 0)
			mc->reg = atoi(val);
		else if (strcmp(key, "reg_right") == 0)
			mc->rreg = atoi(val);
		else if (strcmp(key, "shift") == 0)
			mc->shift = mc->rshift = atoi(val);
		else if (strcmp(key, "shift_left") == 0)
			mc->shift = atoi(val);
		else if (strcmp(key, "shift_right") == 0)
			mc->rshift = atoi(val);
		else if (strcmp(key, "max") == 0)
			mc->max = mc->platform_max = atoi(val);
		else if (strcmp(key, "invert") == 0)
			mc->invert = atoi(val);
		else if (strcmp(key, "tlv_array") == 0) {
			if(val[0]) {
				err = add_ref(elem, val);
				if (err < 0)
					return err;
			}
		}
#endif
	}

	return 0;
}

/* Parse Controls.
 *
 * Each Control is described in new section
 * Supported control types: Mixer
 *
 * SectionControl."control name" {
 * 		Comment "optional comments"
 *
 *		Mixer [
 *			...
 * 		]
 *		Enum [
 *			...
 * 		]
 *		Bytes [
 *			...
 * 		]
 *	}
 */
static int parse_control(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	list_add_tail(&elem->list, &soc_tplg->control_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "Comment") == 0)
			continue;

		/* mixer control */
		if (strcmp(id, "Mixer") == 0) {
			err = parse_mixer(n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse mixer\n");
				return err;
			}
			continue;
		}

		/* enumerated control */
		if (strcmp(id, "Enum") == 0) {
			err = parse_enum(n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse enum\n");
				return err;
			}
			continue;
		}

		/* bytes control */
		if (strcmp(id, "Bytes") == 0) {
			err = parse_bytes(n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse bytes\n");
				return err;
			}
			continue;
		}

		tplg_error("error: Control '%s': Unsupported control type '%s'\n",
			elem->id, id);
	}

	return 0;
}

static int parse_referenced_mixer(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_mixer_control *mc;

	return 0;

	tplg_dbg("Referenced Mixer: %s\n", elem->id);
	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for control mixer definition");
		return -EINVAL;
	}

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -ENOMEM;
	elem->mixer_ctrl = mc;
	elem->type = SND_SOC_TPLG_MIXER;

	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	mc->hdr.index = SOC_CONTROL_IO_EXT |
		SOC_CONTROL_ID(1, 1, 0);
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;
	/* TODO: mc->hdr.tlv_size, need to get tlv info */
	mc->priv.size  = 0;

	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for sequence command");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if(snd_config_get_string(n, &val) < 0) {
			tplg_error("Mixer %s: invalid %s definition\n", elem->id, key);
			return -EINVAL;
		}
		tplg_dbg("\t%s: %s\n",key, val);

#if 0
		if (strcmp(key, "reg") == 0)
			mc->reg = mc->rreg = atoi(val);
		else if (strcmp(key, "reg_left") == 0)
			mc->reg = atoi(val);
		else if (strcmp(key, "reg_right") == 0)
			mc->rreg = atoi(val);
		else if (strcmp(key, "shift") == 0)
			mc->shift = mc->rshift = atoi(val);
		else if (strcmp(key, "shift_left") == 0)
			mc->shift = atoi(val);
		else if (strcmp(key, "shift_right") == 0)
			mc->rshift = atoi(val);
		else if (strcmp(key, "max") == 0)
			mc->max = mc->platform_max = atoi(val);
		else if (strcmp(key, "invert") == 0)
			mc->invert = atoi(val);
		else if (strcmp(key, "tlv_array") == 0) {
			if(val[0]) {
				err = add_ref(elem, val);
				if (err < 0)
					return err;
			}
		}
#endif
	}

	return 0;
}

static int parse_mixer_array(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for dapm graph definition\n");
		return -EINVAL;
	}

	elem = elem_new();
	if (!elem)
		return -ENOMEM;
	list_add_tail(&elem->list, &soc_tplg->mixer_array_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	elem->type = SND_SOC_TPLG_MIXER_ARRAY;

	tplg_dbg("Mixer array '%s'\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "Mixer") == 0) {
			err = parse_referenced_mixer(n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse verb enable sequence\n");
				return err;
			}
			continue;
		}
	}

	return 0;
}

/* Supported widget type: AIF_IN AIF_OUT MIXER
 *
 */
static int parse_widget(snd_config_t *cfg, soc_tplg_elem_t *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *type;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_dapm_widget *widget;
	int widget_type;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for dapm widget definition\n");
		return -EINVAL;
	}

	widget = calloc(1, sizeof(*widget));
	if (!widget)
		return -ENOMEM;

	elem->widget = widget;
	elem->type = SND_SOC_TPLG_DAPM_WIDGET;
	strncpy(widget->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	/* check widget type */
	snd_config_get_id(cfg, &type);
	tplg_dbg("Widget %s, type %s\n", elem->id, type);
	widget_type = lookup_widget(type);
	if (widget_type < 0){
		tplg_error("Widget '%s': Unsupported widget type %s\n", elem->id, type);
	}
	widget->id = widget_type;

	/* todo: fill widget data */
	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for sequence command");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if(snd_config_get_string(n, &val) < 0) {
			tplg_error("Widget %s: invalid %s definition\n", elem->id, key);
			return -EINVAL;
		}
		tplg_dbg("\t%s: %s\n",key, val);

		if (strcmp(key, "stream_name") == 0)
			strncpy(widget->sname, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
		else if (strcmp(key, "reg") == 0)
			widget->reg = atoi(val);
		else if (strcmp(key, "shift") == 0)
			widget->shift = atoi(val);
		else if (strcmp(key, "invert") == 0)
			widget->invert = atoi(val);
		else if (strcmp(key, "controls") == 0) {
			if(val[0]) {
				err = add_ref(elem, val);
				if (err < 0)
					return err;
			}
		}
	}
	return 0;
}

static int parse_dapm_widget(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;
	list_add_tail(&elem->list, &soc_tplg->widget_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}
		err = parse_widget(n, elem);
		if (err < 0) {
			tplg_error("error: failed to parse widget %s, type %s\n", elem->id, id);
			return err;
		}
		continue;
	}

	return 0;
}

static int parse_routes(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int idx = 0;
	struct soc_tplg_elem *elem;
	struct snd_soc_tplg_dapm_graph_elem *route = NULL;

	snd_config_for_each(i, next, cfg) {
		const char *val;

		idx++;
		idx %= 3;
		n = snd_config_iterator_entry(i);
		if (snd_config_get_string(n, &val) < 0) {
			continue;
		}

		if (idx == 1) {
			elem = elem_new();
			if (!elem)
				return -ENOMEM;
			list_add_tail(&elem->list, &soc_tplg->route_list);
			strcpy(elem->id, "route");
			elem->type = SND_SOC_TPLG_DAPM_GRAPH;

			route= calloc(1, sizeof(*route));
			if (!route)
				return -ENOMEM;
			elem->route = route;
			strncpy(route->sink, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

		}
		else if (idx == 2)
			strncpy(route->control, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
		else {
			strncpy(route->source, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
			tplg_dbg("route: sink '%s', control '%s', source '%s'\n",
				route->sink, route->control, route->source);
		}
	}

	return 0;
}

static int parse_dapm_graph(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err;
	const char *graph_id;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for dapm graph definition\n");
		return -EINVAL;
	}
	snd_config_get_id(cfg, &graph_id);

	snd_config_for_each(i, next, cfg) {
		const char *id;

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "Routes") == 0) {
			err = parse_routes(soc_tplg, n);
			if (err < 0) {
				tplg_error("error: failed to parse dapm graph %s\n", graph_id);
				return err;
			}
			continue;
		}
	}

	return 0;
}

static int parse_pcm_dai_stream(snd_config_t *cfg, struct soc_tplg_elem *elem,
	int stream_dir)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	int err, idx = 0;
	const char *key = NULL, *val = NULL;
	struct snd_soc_tplg_pcm_dai *pcm_dai = elem->pcm;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for stream definition\n");
		return -EINVAL;
	}

	snd_config_for_each(i, next, cfg) {
		const char *id;
		idx ^= 1;
		n = snd_config_iterator_entry(i);
		err = snd_config_get_id(n, &id);
		if (err < 0)
			continue;

		if (snd_config_get_type(n) != SND_CONFIG_TYPE_STRING) {
			tplg_error("error: string type is expected for stream members");
			return -EINVAL;
		}

		if (idx == 1) {
			snd_config_get_string(n, &key);
			continue;
		}

		if(snd_config_get_string(n, &val) < 0) {
			tplg_error("pcm_dai %s: invalid '%s' definition\n", elem->id, key);
			return -EINVAL;
		}
		//tplg_dbg("\t%s: %s\n",key, val);

		if (strcmp(key, "stream_name") == 0) {
			if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
				strncpy(pcm_dai->caps[0].name, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
			else
				strncpy(pcm_dai->caps[1].name, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
		}
	}

	return 0;
}

static int parse_pcm_dai(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err = 0;
	struct soc_tplg_elem *elem;
	struct snd_soc_tplg_pcm_dai *pcm_dai;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("error: compound is expected for pcm_dai definition\n");
		return -EINVAL;
	}

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	list_add_tail(&elem->list, &soc_tplg->pcm_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	pcm_dai = calloc(1, sizeof(*pcm_dai));
	if (!pcm_dai)
		return -ENOMEM;
	elem->pcm = pcm_dai;
	elem->type = SND_SOC_TPLG_PCM;

	printf("find pcm_dai '%s'\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "Playback") == 0) {
			err = parse_pcm_dai_stream(n, elem,
				SNDRV_PCM_STREAM_PLAYBACK);
			if (err < 0) {
				tplg_error("error: failed to parse FE playback");
				return err;
			}
			continue;
		}

		if (strcmp(id, "Capture") == 0) {
			err = parse_pcm_dai_stream(n, elem,
				SNDRV_PCM_STREAM_CAPTURE);
			if (err < 0) {
				tplg_error("error: failed to parse FE capture");
				return err;
			}
			continue;
		}
	}

	return 0;
}

static int tplg_parse_config(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err;

	if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
		tplg_error("compound type expected for master file");
		return -EINVAL;
	}

	/* parse topology config sections */
	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "SectionTLV") == 0) {
			err = parse_compound(soc_tplg, n, parse_tlv);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionControl") == 0) {
			err = parse_compound(soc_tplg, n, parse_control);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionWidget") == 0) {
			err = parse_compound(soc_tplg, n, parse_dapm_widget);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionGraph") == 0) {
			err = parse_compound(soc_tplg, n, parse_dapm_graph);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionFe") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_dai);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionMixer") == 0) {
			err = parse_compound(soc_tplg, n, parse_mixer_array);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionText") == 0) {
			err = parse_compound(soc_tplg, n, parse_text);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionData") == 0) {
			err = parse_compound(soc_tplg, n, parse_data);
			if (err < 0)
				return err;
			continue;
		}

		tplg_error("uknown section %s\n", id);
	}
	return 0;
}

static int tplg_load_config(const char *file, snd_config_t **cfg)
{
	FILE *fp;
	snd_input_t *in;
	snd_config_t *top;
	int err;

	fp = fopen(file, "r");
	if (fp == NULL) {
		err = -errno;
		goto __err;
	}

	err = snd_input_stdio_attach(&in, fp, 1);
	if (err < 0) {
	      __err:
		fprintf(stdout, "could not open configuration file %s", file);
		return err;
	}
	err = snd_config_top(&top);
	if (err < 0)
		return err;

	err = snd_config_load(top, in);
	if (err < 0) {
		fprintf(stdout, "could not load configuration file %s", file);
		snd_config_delete(top);
		return err;
	}

	err = snd_input_close(in);
	if (err < 0) {
		snd_config_delete(top);
		return err;
	}

	*cfg = top;
	return 0;
}

static int check_routes(struct soc_tplg_priv *soc_tplg)
{
	struct list_head *base, *pos, *npos;
	soc_tplg_elem_t *elem;
	struct snd_soc_tplg_dapm_graph_elem *route;

	base = &soc_tplg->route_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, soc_tplg_elem_t, list);
		if (!elem->route || elem->type != SND_SOC_TPLG_DAPM_GRAPH) {
			tplg_error("Invalid route 's'\n", elem->id);
			return -EINVAL;
		}

		route = elem->route;
		tplg_dbg("\nCheck route: sink '%s', control '%s', source '%s'\n",
			route->sink, route->control, route->source);

		if (strlen(route->sink)
			&& !lookup_element(&soc_tplg->widget_list, route->sink,
			SND_SOC_TPLG_DAPM_WIDGET)
			&& !lookup_pcm_dai_stream(&soc_tplg->pcm_list, route->sink)) {
			tplg_error("Route: Undefined sink widget/stream '%s'\n",
				route->sink);
			return -EINVAL;
		}

		if (strlen(route->control)
			&& !lookup_element(&soc_tplg->control_list, route->control,
			SND_SOC_TPLG_MIXER)) {
			tplg_error("Route: Undefined mixer control '%s'\n",
				route->control);
			return -EINVAL;
		}

		if (strlen(route->source)
			&& !lookup_element(&soc_tplg->widget_list, route->source,
			SND_SOC_TPLG_DAPM_WIDGET)
			&& !lookup_pcm_dai_stream(&soc_tplg->pcm_list, route->source)) {
			tplg_error("Route: Undefined source widget/stream '%s'\n",
				route->source);
			return -EINVAL;
		}
	}

	return 0;
}

static int check_referenced_tlv(struct soc_tplg_priv *soc_tplg,
				soc_tplg_elem_t *elem)
{
	soc_tplg_ref_t *ref;
	struct list_head *base, *pos, *npos;

	tplg_dbg("\nCheck control tlv: '%s'\n", elem->id);

	base = &elem->ref_list;
	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, soc_tplg_ref_t, list);
		if (ref->id && !ref->elem) {
			ref->elem = lookup_element(&soc_tplg->tlv_list,
				ref->id, SND_SOC_TPLG_TLV);
			if (!ref->elem) {
				tplg_error("Cannot find tlv '%s' referenced by"
					" control '%s'\n", ref->id, elem->id);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int check_controls(struct soc_tplg_priv *soc_tplg)
{

	struct list_head *base, *pos, *npos;
	soc_tplg_elem_t *elem;
	int err;

	base = &soc_tplg->control_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, soc_tplg_elem_t, list);
		if (!elem->mixer_ctrl|| elem->type != SND_SOC_TPLG_MIXER) {
			tplg_error("Invalid control 's'\n", elem->id);
			return -EINVAL;
		}

		err = check_referenced_tlv(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	return 0;
}

static int check_referenced_controls(struct soc_tplg_priv *soc_tplg,
	soc_tplg_elem_t *elem)
{
	return 0;
}

static int check_widgets(struct soc_tplg_priv *soc_tplg)
{

	struct list_head *base, *pos, *npos;
	soc_tplg_elem_t *elem;
	int err;

	base = &soc_tplg->widget_list;
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, soc_tplg_elem_t, list);
		if (!elem->widget|| elem->type != SND_SOC_TPLG_DAPM_WIDGET) {
			tplg_error("Invalid widget '%s'\n", elem->id);
			return -EINVAL;
		}

		err = check_referenced_controls(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	return 0;
}

static int tplg_check_integ(struct soc_tplg_priv *soc_tplg)
{
	int err;

	err = check_controls(soc_tplg);
	if (err <  0)
		return err;

	err = check_widgets(soc_tplg);
	if (err <  0)
		return err;

	err = check_routes(soc_tplg);
	if (err <  0)
		return err;

	return err;
}

int parse_conf(struct soc_tplg_priv *soc_tplg, const char *filename)
{
	snd_config_t *cfg;
	int err = 0;

	err = tplg_load_config(filename, &cfg);
	if (err < 0) {
		tplg_error("Failed to load topology file %s\n",
			filename);
		return err;
	}

	err = tplg_parse_config(soc_tplg, cfg);
	if (err < 0) {
		tplg_error("Failed to parse topology\n");
		goto out;
	}

	err = tplg_check_integ(soc_tplg);
	if (err < 0) {
		tplg_error("Failed to check topology integrity\n");
		goto out;
	}

out:
	snd_config_delete(cfg);
	return err;
}

