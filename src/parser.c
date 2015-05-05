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

static const struct map_elem control_map[] = {
	{"volsw", SND_SOC_TPLG_CTL_VOLSW},
	{"volsw_sx", SND_SOC_TPLG_CTL_VOLSW_SX},
	{"volsw_xr_sx", SND_SOC_TPLG_CTL_VOLSW_XR_SX},
	{"enum", SND_SOC_TPLG_CTL_ENUM},
	{"bytes", SND_SOC_TPLG_CTL_BYTES},
	{"enum_value", SND_SOC_TPLG_CTL_ENUM_VALUE},
	{"range", SND_SOC_TPLG_CTL_RANGE},
	{"strobe", SND_SOC_TPLG_CTL_STROBE},
};

static const struct map_elem widget_control_map[] = {
	{"volsw", SND_SOC_TPLG_DAPM_CTL_VOLSW},
	{"enum_double", SND_SOC_TPLG_DAPM_CTL_ENUM_DOUBLE},
	{"enum_virt", SND_SOC_TPLG_DAPM_CTL_ENUM_VIRT},
	{"enum_value", SND_SOC_TPLG_DAPM_CTL_ENUM_VALUE},
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
	INIT_LIST_HEAD(&soc_tplg->pdata_list);
	INIT_LIST_HEAD(&soc_tplg->text_list);

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
	free_elem_list(&soc_tplg->pdata_list);
	free_elem_list(&soc_tplg->text_list);

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

static int lookup_channel(const char *c)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(channel_map); i++) {
		if (strcmp(channel_map[i].name, c) == 0)
			return channel_map[i].id;
	}

	return -EINVAL;
}

static int lookup_ops(const char *c)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(control_map); i++) {
		if (strcmp(control_map[i].name, c) == 0)
			return control_map[i].id;
	}

	return -EINVAL;
}

/*
 * Parse compound
 */
static int parse_compound(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	  int (*fcn)(struct soc_tplg_priv *, snd_config_t *, void *), void *private)
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

	/* parse compound */
	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);

		if (snd_config_get_type(cfg) != SND_CONFIG_TYPE_COMPOUND) {
			tplg_error("compound type expected for %s, is %d",
				id, snd_config_get_type(cfg));
			return -EINVAL;
		}

		err = fcn(soc_tplg, n, private);
		if (err < 0)
			return err;
	}

	return 0;
}

static int parse_data_file(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	struct snd_soc_tplg_private *priv;
	const char *value = NULL;

	tplg_dbg(" Data DataFile: %s\n", elem->id);

	if (snd_config_get_string(cfg, &value) < 0)
		return -EINVAL;

	priv = calloc(1, sizeof(*priv) + PATH_MAX);
	if (!priv)
		return -ENOMEM;	
	
	elem->data = priv;
	priv->size = PATH_MAX;

	strncpy(priv->data, value, PATH_MAX);
	tplg_dbg("\t%s\n", priv->data);

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
static int parse_data(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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
	elem->type = SND_SOC_TPLG_DATA;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "DataFile") == 0) {
			err = parse_data_file(soc_tplg, n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse data file");
				return err;
			}
			continue;
		}
	}

	return err;
}

#define TEXT_SIZE_MAX	(SND_SOC_TPLG_NUM_TEXTS * SNDRV_CTL_ELEM_ID_NAME_MAXLEN)

static int parse_text_values(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *value = NULL;
	int j = 0;

	tplg_dbg(" Text Values: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);

		if (j == SND_SOC_TPLG_NUM_TEXTS) {
			tplg_dbg("error: text string number exceeds %d\n", j);
			return -ENOMEM;
		}

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		strncpy(&elem->texts[j][0], value, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
		tplg_dbg("\t%s\n", &elem->texts[j][0]);
		
		j++;
	}

	return 0;
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
static int parse_text(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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
	elem->type = SND_SOC_TPLG_TEXT;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;
		
		if (strcmp(id, "Values") == 0) {
			err = parse_text_values(soc_tplg, n, elem);
			if (err < 0) {
				tplg_error("error: failed to parse text values");
				return err;
			}
			continue;
		}
	}

	return err;
}

/* Parse a channel.
 *
 * Channel."channel_map.name" {
 *		reg "0"	(register)
 *		shift "0" (shift)
 * }
 */
static int parse_channel(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct snd_soc_tplg_channel *channel = private;
	const char *id, *value;

	snd_config_get_id(cfg, &id);
	channel->id = lookup_channel(id);
	if (channel->id < 0) {
		tplg_error("invalid channel %s\n", id);
		return -EINVAL;
	}

	tplg_dbg("\tChannel %s\n", id);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		/* get id */
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		if (strcmp(id, "reg") == 0)
			channel->reg = atoi(value);
		else if (strcmp(id, "shift") == 0)
			channel->shift = atoi(value);

		tplg_dbg("\t\t%s = %s\n", id, value);
	}

	return 0;
}

/* Parse Control operations.
 *
 * Ops [
 *	info <string>
 *	get <string>
 *	put <string>
 * }
 */
static int parse_ops(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct snd_soc_tplg_ctl_hdr *hdr = private;
	const char *id, *value;
	unsigned int info = 0, get = 0, put = 0;

	tplg_dbg("\tOps\n");

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		/* get id */
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		if (strcmp(id, "info") == 0) {
			info = lookup_ops(value);
			if (info < 0)
				info = atoi(value);
		} else if (strcmp(id, "get") == 0) {
			put = lookup_ops(value);
			if (put < 0)
			put = atoi(value);
		} else if (strcmp(id, "put") == 0) {
			get = lookup_ops(value);
			if (get < 0)
				get = atoi(value);
		}

		tplg_dbg("\t\t%s = %s\n", id, value);
	}

	hdr->type = SND_SOC_TPLG_CTL_SID(get, put, info);
	return 0;
}

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
	const char *id = NULL, *value = NULL;
	int *data;

	tplg_dbg(" TLV DBScale: %s\n", elem->id);

	tplg_tlv = calloc(1, sizeof(*tplg_tlv) + TLV_DB_SCALE_SIZE);
	if (!tplg_tlv)
		return -ENOMEM;
	data = (int*)(tplg_tlv + 1);

	elem->tlv = tplg_tlv;
	tplg_tlv->numid = SNDRV_CTL_TLVT_DB_SCALE;
	tplg_tlv->size = TLV_DB_SCALE_SIZE;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		/* get ID */
		if (snd_config_get_id(n, &id) < 0) {
			tplg_error("cant get ID\n");
			return -EINVAL;
		}

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		tplg_dbg("\t%s = %s\n", id, value);

		/* get TLV data */
		if (strcmp(id, "min") == 0)
			data[0] = atoi(value);
		else if (strcmp(id, "step") == 0)
			data[1] = atoi(value);
		else if (strcmp(id, "mute") == 0)
			data[2] = atoi(value);
		else
			tplg_error("unknown key %s\n", id);
	}

	return 0;
}

/* Parse TLV.
 *
 * Each TLV is described in new section
 * Supported TLV types: DBScale.
 *
 * SectionTLV."tlv name" {
 *		TlvType [
 *
 * 		]
 *	}
 */
static int parse_tlv(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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
		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "DBScale") == 0) {
			err = parse_tlv_dbscale(soc_tplg, n, elem);
			if (err < 0) {
				tplg_error("error: failed to DBScale");
				return err;
			}
			continue;
		}
	}

	return err;
}

/* Parse Control Bytes
 *
 * Each Control is described in new section
 * Supported control types: Byte
 *
 * SectionControlBytes."control name" {
 * 	Comment "optional comments"
 *
 *	Index "1"
 *	base "0"
 *	num_regs "16"
 *	mask "0xff"
 * }
 */
static int parse_control_bytes(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_bytes_ext *be;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;	

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	be = calloc(1, sizeof(*be));
	if (!be) {
		free(elem);
		return -ENOMEM;
	}

	/* add new element to control list */
	list_add_tail(&elem->list, &soc_tplg->control_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	elem->bytes_ext = be;
	elem->type = SND_SOC_TPLG_BYTES_EXT;
	strncpy(be->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	// TODO: get type ops from lookup table based on name
	//be->hdr.type = SOC_CONTROL_IO_EXT |
	//	SOC_CONTROL_ID(1, 1, 0);
	
	tplg_dbg(" Control Bytes: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "Comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "Index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->hdr.index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, be->hdr.index);
			continue;
		}

		if (strcmp(id, "Base") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->base = atoi(val);
			tplg_dbg("\t%s: %d\n", id, be->base);
			continue;
		}

		if (strcmp(id, "NumRegs") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->num_regs = atoi(val);
			tplg_dbg("\t%s: %d\n", id, be->num_regs);
			continue;
		}

		if (strcmp(id, "Mask") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->mask = strtol(val, NULL, 16);
			tplg_dbg("\t%s: %d\n", id, be->mask);
			continue;
		}
	}

	return 0;
}

/* Parse Control Enums.
 *
 * Each Control is described in new section
 * Supported control types: Mixer
 *
 * SectionControlMixer."control name" {
 * 	Comment "optional comments"
 *
 *	Index <int>
 *	texts "EQU1" 
 *		
 *	Channel."name" [
 *	]
 *
 *	max <int>
 *	invert <boolean>
 *	Ops [
 *	]
 *
 *	tlv "hsw_vol_tlv"
 * }
 */
static int parse_control_enum(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	struct snd_soc_tplg_enum_control *ec;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	ec = calloc(1, sizeof(*ec));
	if (!ec) {
		free(elem);
		return -ENOMEM;
	}

	/* add new element to control list */
	list_add_tail(&elem->list, &soc_tplg->control_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	/* init new mixer */	
	elem->enum_ctrl = ec;
	elem->type = SND_SOC_TPLG_MIXER;
	strncpy(ec->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	ec->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;

	// TODO: get type ops from lookup table based on name
	//ec->hdr.type = SOC_CONTROL_IO_EXT |
	//	SOC_CONTROL_ID(1, 1, 0);

	tplg_dbg(" Control Enum: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;
 
		/* skip comments */
		if (strcmp(id, "Comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "Index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			ec->hdr.index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, ec->hdr.index);
			continue;
		}

		if (strcmp(id, "Texts") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			strncpy(elem->text_ref, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
			tplg_dbg("\t%s: %s\n", id, elem->text_ref);
			continue;
		}
		
		if (strcmp(id, "Channel") == 0) {
			err = parse_compound(soc_tplg, n, parse_channel,
				ec->channel);
			if (err < 0)
				return err;
			
			ec->num_channels = err;
			continue;
		}

		if (strcmp(id, "Ops") == 0) {
			err = parse_compound(soc_tplg, n, parse_ops, &ec->hdr);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "Data") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			strncpy(elem->data_ref, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
			tplg_dbg("\t%s: %s\n", id, elem->data_ref);
			continue;
		}
	}

	return 0;
}

/* Parse Controls.
 *
 * Each Control is described in new section
 * Supported control types: Mixer
 *
 * SectionControlMixer."control name" {
 * 	Comment "optional comments"
 *
 *	Index <int>
 *		
 *	Channel."name" [
 *	]
 *
 *	max <int>
 *	invert <boolean>
 *	Ops [
 *	]
 *
 *	tlv "hsw_vol_tlv"
 * }
 */
static int parse_control_mixer(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_mixer_control *mc;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	mc = calloc(1, sizeof(*mc));
	if (!mc) {
		free(elem);
		return -ENOMEM;
	}

	/* add new element to control list */
	list_add_tail(&elem->list, &soc_tplg->control_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	/* init new mixer */	
	elem->mixer_ctrl = mc;
	elem->type = SND_SOC_TPLG_MIXER;
	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;

	// TODO: get type ops from lookup table based on name
	//mc->hdr.type = SOC_CONTROL_IO_EXT |
	//	SOC_CONTROL_ID(1, 1, 0);

	tplg_dbg(" Control Mixer: %s\n", elem->id);

	/* giterate trough each mixer elment */
	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "Comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "Index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, mc->hdr.index);
			continue;
		}

		if (strcmp(id, "Channel") == 0) {

			err = parse_compound(soc_tplg, n, parse_channel,
				mc->channel);
			if (err < 0)
				return err;

			mc->num_channels = err;
			continue;
		}

		if (strcmp(id, "max") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			mc->max = atoi(val);
			tplg_dbg("\t%s: %d\n", id, mc->max);
			continue;
		}

		if (strcmp(id, "invert") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			if (strcmp(val, "true") == 0)
				mc->invert = 1;
			else if (strcmp(val, "false") == 0)
				mc->invert = 0;

			tplg_dbg("\t%s: %d\n", id, mc->invert);
			continue;
		}

		if (strcmp(id, "Ops") == 0) {
			err = parse_compound(soc_tplg, n, parse_ops, &mc->hdr);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "tlv_array") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			err = add_ref(elem, val);
			if (err < 0)
				return err;				

			tplg_dbg("\t%s: %s\n", id, val);
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

		if (strcmp(id, "Index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

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

static int parse_dapm_widget(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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

static int parse_dapm_graph(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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

static int parse_pcm_dai(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
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
			err = parse_compound(soc_tplg, n, parse_tlv, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionControlMixer") == 0) {
			err = parse_compound(soc_tplg, n, parse_control_mixer, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionControlEnum") == 0) {
			err = parse_compound(soc_tplg, n, parse_control_enum, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionControlBytes") == 0) {
			err = parse_compound(soc_tplg, n, parse_control_bytes, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionWidget") == 0) {
			err = parse_compound(soc_tplg, n, parse_dapm_widget, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionGraph") == 0) {
			err = parse_compound(soc_tplg, n, parse_dapm_graph, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionFe") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_dai, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionText") == 0) {
			err = parse_compound(soc_tplg, n, parse_text, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionData") == 0) {
			err = parse_compound(soc_tplg, n, parse_data, NULL);
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

