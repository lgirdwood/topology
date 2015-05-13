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

static int parse_compound(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	int (*fcn)(struct soc_tplg_priv *, snd_config_t *, void *),
	void *private);

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

static const struct map_elem pcm_format_map[] = {
	{"S16_LE", SNDRV_PCM_FORMAT_S16_LE},
	{"S16_BE", SNDRV_PCM_FORMAT_S16_BE},
	{"U16_LE", SNDRV_PCM_FORMAT_U16_LE},
	{"U16_BE", SNDRV_PCM_FORMAT_U16_BE},
	{"S24_LE", SNDRV_PCM_FORMAT_S24_LE},
	{"S24_BE", SNDRV_PCM_FORMAT_S24_BE},
	{"U24_LE", SNDRV_PCM_FORMAT_U24_LE},
	{"U24_BE", SNDRV_PCM_FORMAT_U24_BE},
	{"S32_LE", SNDRV_PCM_FORMAT_S32_LE},
	{"S32_BE", SNDRV_PCM_FORMAT_S32_BE},
	{"U32_LE", SNDRV_PCM_FORMAT_U32_LE},
	{"U32_BE", SNDRV_PCM_FORMAT_U32_BE},
};

static void tplg_error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
}

static inline int add_ref(struct soc_tplg_elem *elem, int type,
	const char* id)
{
	struct soc_tplg_ref *ref;

	ref = calloc(1, sizeof(*ref));
	if (!ref)
		return -ENOMEM;

	strncpy(ref->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	ref->type = type;

	list_add_tail(&ref->list, &elem->ref_list);
	return 0;
}

static void free_ref_list(struct list_head *base)
{
	struct list_head *pos, *npos;
	struct soc_tplg_ref *ref;

	list_for_each_safe(pos, npos, base) {
		ref = list_entry(pos, struct soc_tplg_ref, list);
		printf("\tfree ref %s\n", ref->id);
		list_del(&ref->list);
		free(ref);
	}
}

static struct soc_tplg_elem *elem_new(void)
{
	struct soc_tplg_elem *elem;

	elem = calloc(1, sizeof(*elem));
	if (!elem)
		return NULL;

	INIT_LIST_HEAD(&elem->ref_list);
	return elem;
}

static void elem_free(struct soc_tplg_elem *elem)
{
	printf("free element %s\n", elem->id);
	free_ref_list(&elem->ref_list);
	free(elem);
}

static void free_elem_list(struct list_head *base)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;

	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, struct soc_tplg_elem, list);
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
	INIT_LIST_HEAD(&soc_tplg->pcm_config_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_caps_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_info_list);

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
	free_elem_list(&soc_tplg->pcm_config_list);
	free_elem_list(&soc_tplg->pcm_caps_list);
	free_elem_list(&soc_tplg->pcm_info_list);
	
	free(soc_tplg);
}

static struct soc_tplg_elem *lookup_element(struct list_head *base,
				const char* id,
				u32 type)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;

	//printf("lookup %s, type %d\n",id, type);
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		//printf("\tfound elem '%s', type %d\n", elem->id, elem->type);
		if (!strcmp(elem->id, id) && elem->type == type) {
			return elem;
		}
	}

	return NULL;
}

#if 0
static struct soc_tplg_elem *lookup_pcm_dai_stream(struct list_head *base, const char* id)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;
	struct snd_soc_tplg_pcm_dai *pcm_dai;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		if (elem->type != PARSER_TYPE_PCM)
			return NULL;

		pcm_dai = elem->pcm;
		//printf("\tfound pcm_dai '%s': playback '%s', capture '%s'\n", elem->id, pcm_dai->playback_caps.stream_name, pcm_dai->capture_caps.stream_name);
		if (pcm_dai && (!strcmp(pcm_dai->caps[0].name, id)
			|| !strcmp(pcm_dai->caps[1].name, id)))
			return elem;
	}

	return NULL;
}
#endif

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

#if 0
static int copy_tlv(struct soc_tplg_priv *soc_tplg, const char *tlv_name,
	struct snd_soc_tplg_ctl_tlv *tlv)
{
	struct soc_tplg_elem *tlv_elem;

	tlv_elem = lookup_element(&soc_tplg->tlv_list, tlv_name,
		PARSER_TYPE_TLV);
	
	if (tlv_elem == NULL) {
		tplg_error("Cannot find tlv '%s'\n", tlv_name);
		return -EINVAL;
	}

	memcpy(tlv, tlv_elem->tlv, sizeof(*tlv));

	return 0;
}
#endif

static int parse_data_file(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	struct snd_soc_tplg_private *priv;
	const char *value = NULL;

	tplg_dbg(" data DataFile: %s\n", elem->id);

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

/* Parse Private data.
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
	elem->type = PARSER_TYPE_DATA;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0) {
			continue;
		}

		if (strcmp(id, "file") == 0) {
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

/* Parse Private data.
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
	elem->type = PARSER_TYPE_TEXT;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;
		
		if (strcmp(id, "values") == 0) {
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
 * channel."channel_map.name" {
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

	channel->size = sizeof(*channel);
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

static int parse_dapm_mixers(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *value = NULL;

	tplg_dbg(" DAPM Mixer Controls: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		add_ref(elem, PARSER_TYPE_MIXER, value);
		tplg_dbg("\t\t %s\n", value);
	}

	return 0;
}

static int parse_dapm_enums(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *value = NULL;

	tplg_dbg(" DAPM Enum Controls: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);

		/* get value */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		add_ref(elem, PARSER_TYPE_ENUM, value);
		tplg_dbg("\t\t %s\n", value);
	}

	return 0;
}

/* Parse Control operations.
 *
 * ops [
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

	tplg_dbg("\tOps\n");
	hdr->size = sizeof(*hdr);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		/* get id */
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* get value - try strings then ints */
		if (snd_config_get_string(n, &value) < 0)
			continue;

		if (strcmp(id, "info") == 0) {
			hdr->ops.info = lookup_ops(value);
			if (hdr->ops.info < 0)
				hdr->ops.info = atoi(value);
		} else if (strcmp(id, "get") == 0) {
			hdr->ops.put = lookup_ops(value);
			if (hdr->ops.put < 0)
				hdr->ops.put = atoi(value);
		} else if (strcmp(id, "put") == 0) {
			hdr->ops.get = lookup_ops(value);
			if (hdr->ops.get < 0)
				hdr->ops.get = atoi(value);
		}

		tplg_dbg("\t\t%s = %s\n", id, value);
	}

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

	tplg_tlv = calloc(1, sizeof(*tplg_tlv));
	if (!tplg_tlv)
		return -ENOMEM;
	data = (int*)(tplg_tlv->data);

	elem->tlv = tplg_tlv;
	tplg_tlv->numid = SNDRV_CTL_TLVT_DB_SCALE;
	tplg_tlv->size = sizeof(*tplg_tlv);

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

	/* SND_SOC_TPLG_TLV_SIZE must be > 3 */
	tplg_tlv->count = 3;

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
	elem->type = PARSER_TYPE_TLV;
	elem->size = sizeof(struct snd_soc_tplg_ctl_tlv);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "scale") == 0) {
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
 * 	comment "optional comments"
 *
 *	index "1"
 *	base "0"
 *	num_regs "16"
 *	mask "0xff"
 * }
 */
static int parse_control_bytes(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_bytes_control *be;
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
	elem->type = PARSER_TYPE_BYTES;
	elem->size = be->size = sizeof(struct snd_soc_tplg_bytes_control);
	strncpy(be->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	
	tplg_dbg(" Control Bytes: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

		if (strcmp(id, "base") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->base = atoi(val);
			tplg_dbg("\t%s: %d\n", id, be->base);
			continue;
		}

		if (strcmp(id, "num_regs") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->num_regs = atoi(val);
			tplg_dbg("\t%s: %d\n", id, be->num_regs);
			continue;
		}

		if (strcmp(id, "mask") == 0) {
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
 * 	comment "optional comments"
 *
 *	index <int>
 *	texts "EQU1" 
 *		
 *	channel."name" [
 *	]
 *
 *	max <int>
 *	invert <boolean>
 *	ops [
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
	elem->type = PARSER_TYPE_ENUM;
	strncpy(ec->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	ec->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;
	elem->size = ec->size = sizeof(*ec);

	tplg_dbg(" Control Enum: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;
 
		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

		if (strcmp(id, "texts") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			add_ref(elem, PARSER_TYPE_TEXT, val);
			tplg_dbg("\t%s: %s\n", id, val);
			continue;
		}
		
		if (strcmp(id, "channel") == 0) {
			err = parse_compound(soc_tplg, n, parse_channel,
				ec->channel);
			if (err < 0)
				return err;
			
			ec->num_channels = err;
			continue;
		}

		if (strcmp(id, "ops") == 0) {
			err = parse_compound(soc_tplg, n, parse_ops, &ec->hdr);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "data") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			add_ref(elem, PARSER_TYPE_DATA, val);
			tplg_dbg("\t%s: %s\n", id, val);
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
 * 	comment "optional comments"
 *
 *	index <int>
 *		
 *	channel."name" [
 *	]
 *
 *	max <int>
 *	invert <boolean>
 *	ops [
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
	elem->type = PARSER_TYPE_MIXER;
	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;
	elem->size = mc->size = sizeof(*mc);

	tplg_dbg(" Control Mixer: %s\n", elem->id);

	/* giterate trough each mixer elment */
	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

		if (strcmp(id, "channel") == 0) {

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

		if (strcmp(id, "ops") == 0) {
			err = parse_compound(soc_tplg, n, parse_ops, &mc->hdr);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "tlv") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			err = add_ref(elem, PARSER_TYPE_TLV, val);
			if (err < 0)
				return err;				

			tplg_dbg("\t%s: %s\n", id, val);
			continue;
		}
	}

	return 0;
}

/* Parse widget
 *
 * SectionWidget."widget name" {
 *
 *	index
 *	type
 *	no_pm
 *	enum
 * }
 */
static int parse_dapm_widget(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_dapm_widget *widget;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int widget_type, err;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	widget = calloc(1, sizeof(*widget));
	if (!widget) {
		free(elem);
		return -ENOMEM;
	}

	/* add new element to widget list */
	list_add_tail(&elem->list, &soc_tplg->widget_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	elem->widget = widget;
	elem->type = PARSER_TYPE_DAPM_WIDGET;
	strncpy(widget->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	elem->size = widget->size = sizeof(*widget);

	tplg_dbg(" Widget: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

		if (strcmp(id, "type") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			widget_type = lookup_widget(val);
			if (widget_type < 0){
				tplg_error("Widget '%s': Unsupported widget type %s\n",
					elem->id, val);
				return -EINVAL;
			}

			widget->id = widget_type;
			tplg_dbg("\t%s: %s\n", id, val);
			continue;
		}

		if (strcmp(id, "no_pm") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			if (strcmp(val, "true") == 0)
				widget->reg = -1;

			tplg_dbg("\t%s: %s\n", id, val);
			continue;
		}

		if (strcmp(id, "enum") == 0) {
			err = parse_dapm_enums(soc_tplg, n, elem);
			if (err < 0)
				return err;

			continue;			
		}

		if (strcmp(id, "mixer") == 0) {
			err = parse_dapm_mixers(soc_tplg, n, elem);
			if (err < 0)
				return err;

			continue;		
		}

	}

	return 0;
}

static __le64 lookup_pcm_format(const char *c)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pcm_format_map); i++) {
		if (strcmp(pcm_format_map[i].name, c) == 0)
			return pcm_format_map[i].id;
	}

	return -EINVAL;
}

/*
 * Parse a stream.
 */
static int parse_stream(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	const char *id, *val;
	struct snd_soc_tplg_stream *stream = private;
	__le64 format;

	stream->size = sizeof(*stream);

	if (snd_config_get_id(cfg, &id) < 0)
		return -EINVAL;

	if (snd_config_get_string(cfg, &val) < 0)
		return -EINVAL;

	if (strcmp(id, "format") == 0) {
		format = lookup_pcm_format(val);
		if (format < 0) {
			tplg_error("Unsupported stream format %s\n", val);
			return -EINVAL;
		}
		
		stream->format = format;
		tplg_dbg("\t\t%s: %s\n", id, val);
	} else if (strcmp(id, "rate") == 0) {
		stream->rate = atoi(val);		
		tplg_dbg("\t\t%s: %d\n", id, stream->rate);
	} else if (strcmp(id, "channels") == 0) {
		stream->channels = atoi(val);		
		tplg_dbg("\t\t%s: %d\n", id, stream->channels);
	} else if (strcmp(id, "tdm_slot") == 0) {
		stream->tdm_slot = strtol(val, NULL, 16);
		tplg_dbg("\t\t%s: 0x%x\n", id, stream->tdm_slot);
	}

	return 0;
}

/* Parse pcm configuration
 *
 * SectionPCMConfig."PCM config name" {
 *
 *	Playback {
 *		format
 *		rate
 *		channels
 *		tdm_slot
 *	}
 *
 *	Capture {
 *		format
 *		rate
 *		channels
 *		tdm_slot
 *	}
 * }
 */
static int parse_pcm_config(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_stream_config *sc;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	sc = calloc(1, sizeof(*sc));
	if (!sc) {
		free(elem);
		return -ENOMEM;
	}

	list_add_tail(&elem->list, &soc_tplg->pcm_config_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	elem->stream_cfg = sc;
	elem->type = PARSER_TYPE_STREAM_CONFIG;
	sc->size = sizeof(*sc);

	tplg_dbg(" PCM Config: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "Playback") == 0) {

			tplg_dbg("\tPlayback\n");
			err = parse_compound(soc_tplg, n, parse_stream,
				&sc->playback);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "Capture") == 0) {

			tplg_dbg("\tCapture\n");
			err = parse_compound(soc_tplg, n, parse_stream,
				&sc->capture);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}

#if 0
static int split_format(struct snd_soc_tplg_stream_caps *caps, char *str)
{
	char *s = NULL;
	__le64 format;
	int i = 0;

	s = strtok(str, ",");
	while ((s != NULL) && (i < SND_SOC_TPLG_MAX_FORMATS)) {
		format = lookup_pcm_format(s);
		if (format < 0) {
			tplg_error("Unsupported stream format %s\n", s);
			return -EINVAL;
		}

		caps->formats[i] = format;
		s = strtok(NULL, ", ");
		i++;
	}

	return 0;
}


/*
 * Parse a stream capabilities
 */
static int parse_caps(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	const char *id, *val;
	struct snd_soc_tplg_stream_caps *caps = private;
	char *s;
	int err;

	caps->size = sizeof(*caps);

	if (snd_config_get_id(cfg, &id) < 0)
		return -EINVAL;

	if (snd_config_get_string(cfg, &val) < 0)
		return -EINVAL;

	if (strcmp(id, "formats") == 0) {
		s = strdup(val);
		if (s == NULL)
			return -ENOMEM;

		err = split_format(caps, s);
		if (err < 0)
			return err;

		free(s);		
		tplg_dbg("\t\t%s: %s\n", id, val);
	} else if (strcmp(id, "rate_min") == 0) {
		caps->rate_min = atoi(val);
		tplg_dbg("\t\t%s: %d\n", id, caps->rate_min);
	} else if (strcmp(id, "rate_max") == 0) {
		caps->rate_max = atoi(val);
		tplg_dbg("\t\t%s: %d\n", id, caps->rate_max);
	} else if (strcmp(id, "channels_min") == 0) {
		caps->channels_min = atoi(val);
		tplg_dbg("\t\t%s: %d\n", id, caps->channels_min);
	} else if (strcmp(id, "channels_max") == 0) {
		caps->channels_max = atoi(val);
		tplg_dbg("\t\t%s: %d\n", id, caps->channels_max);
	}

	return 0;
}

/*
 * Stream Capabilities
 */
struct snd_soc_tplg_stream_caps {
	__le32 size;		/* in bytes of this structure */
	char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
	__le64 formats[SND_SOC_TPLG_MAX_FORMATS];	/* supported formats SNDRV_PCM_FMTBIT_* */
	__le32 rates;		/* supported rates SNDRV_PCM_RATE_* */
	__le32 rate_min;	/* min rate */
	__le32 rate_max;	/* max rate */
	__le32 channels_min;	/* min channels */
	__le32 channels_max;	/* max channels */
	__le32 periods_min;	/* min number of periods */
	__le32 periods_max;	/* max number of periods */
	__le32 period_size_min;	/* min period size bytes */
	__le32 period_size_max;	/* max period size bytes */
	__le32 buffer_size_min;	/* min buffer size bytes */
	__le32 buffer_size_max;	/* max buffer size bytes */ 
} __attribute__((packed));


/* Parse pcm Capabilities
 *
 * SectionPCMCapabilities." PCM capabilities name" {
 *
 *	Capabilities {
 *		formats "S24_LE, S16_LE"
 *		rate_min "48000"
 *		rate_max "48000"
 *		channels_min "2"
 *		channels_max "2"
 *	}
 * } 
 */
static int parse_pcm_caps(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_stream_caps *sc;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id;
	int err;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	sc = calloc(1, sizeof(*sc));
	if (!sc) {
		free(elem);
		return -ENOMEM;
	}

	list_add_tail(&elem->list, &soc_tplg->pcm_caps_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	sc->size = sizeof(*sc);
	elem->stream_caps = sc;
	elem->type = PARSER_TYPE_STREAM_CAPS;
	strncpy(sc->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	

	tplg_dbg(" PCM Capabilities: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "Capabilities") == 0) {

			tplg_dbg("\tCapabilities\n");
			err = parse_compound(soc_tplg, n, parse_caps, sc);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;	
}

struct snd_soc_tplg_pcm_cap_config_priv {
	struct snd_soc_tplg_pcm_cap_config *cc;
	struct soc_tplg_elem *elem;
};

static int split_config(struct snd_soc_tplg_pcm_cap_config *cc, char *str,
	struct soc_tplg_elem *elem)
{
	char *s;
	int err, i = 0;

	s = strtok(str, ",");
	while ((s != NULL) && (i < SND_SOC_TPLG_MAX_CONFIG)) {
		strncpy(cc->config_names[i], s, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

		err = add_ref(elem, s);
		if (err < 0)
			return err;

		tplg_dbg("\t\tConfig: %s\n", cc->config_names[i]);
		s = strtok(NULL, ",");
		i++;
	}

	cc->config_num = i;
	
	return 0;
}

/*
 * Parse PCM capabilities and configs
 */
static int parse_pcm_cap_config(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	const char *id, *val;
	struct snd_soc_tplg_pcm_cap_config_priv *priv = private;
	struct snd_soc_tplg_pcm_cap_config *cc = priv->cc;
	struct soc_tplg_elem *elem = priv->elem;
	int err = 0;
	char *s;

	if (snd_config_get_id(cfg, &id) < 0)
		return -EINVAL;

	if (snd_config_get_string(cfg, &val) < 0)
		return -EINVAL;

	if (strcmp(id, "Capabilities") == 0) {
		strncpy(cc->caps_name, val, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
		err = add_ref(elem, val);
		if (err < 0)
			return err;

		tplg_dbg("\t\t%s: %s\n", id, val);
	} else if (strcmp(id, "Config") == 0) {
		s = strdup(val);
		if (s == NULL)
			return -ENOMEM;

		err = split_config(cc, s, elem);
		free(s);

		if (err < 0)
			return err;
	}

	return 0;
}

struct snd_soc_tplg_pcm_dai {
	__le32 size;		/* in bytes of this structure */
	char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
	__le32 id;			/* unique ID - used to match */
	__le32 playback;		/* supports playback mode */
	__le32 capture;			/* supports capture mode */
	__le32 compress;		/* 1 = compressed; 0 = PCM */
	__le32 num_configs;		/* number of configs */
	struct snd_soc_tplg_stream_caps caps[2];	/* capabilities */
	struct snd_soc_tplg_stream_config config[0];	/* supported SW/FW configs */
}__attribute__((packed));

/* Parse pcm
 *
 * SectionPCM."System Pin" {
 *
 *	index "1"
 *
 *	# used for binding to the PCM
 *	ID "0"
 *
 *	Playback {
 *		Capabilities "System Playback"
 *		Config "PCM 48k Stereo 24bit"
 *		Config "PCM 48k Stereo 16bit"
 *	}
 *
 *	Capture {
 *		Capabilities "Analog Capture"
 *		Config "PCM 48k Stereo 24bit"
 *		Config "PCM 48k Stereo 16bit"
 *		Config "PCM 48k 2P/4C 16bit"
 *	}
 * }
 */
static int parse_pcm(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_pcm_info *pcm;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;
	struct snd_soc_tplg_pcm_cap_config_priv priv;

	elem = elem_new();
	if (!elem)
		return -ENOMEM;

	pcm = calloc(1, sizeof(*pcm));
	if (!pcm) {
		free(elem);
		return -ENOMEM;
	}

	list_add_tail(&elem->list, &soc_tplg->pcm_info_list);
	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	elem->pcm_info = pcm;
	elem->type = PARSER_TYPE_PCM_INFO;
	strncpy(pcm->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	pcm->size = sizeof(*pcm);
	priv.elem = elem;

	tplg_dbg(" PCM: %s\n", elem->id);

	snd_config_for_each(i, next, cfg) {
		n = snd_config_iterator_entry(i);
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* skip comments */
		if (strcmp(id, "comment") == 0)
			continue;
		if (id[0] == '#')
			continue;

		if (strcmp(id, "index") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			pcm->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, pcm->index);
			continue;
		}

		if (strcmp(id, "ID") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			pcm->id = atoi(val);
			tplg_dbg("\t%s: %d\n", id, pcm->id);
			continue;
		}

		if (strcmp(id, "Playback") == 0) {

			tplg_dbg("\tPlayback\n");
			
			priv.cc = &pcm->playback;
			err = parse_compound(soc_tplg, n, parse_pcm_cap_config,
				&priv);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "Capture") == 0) {

			tplg_dbg("\tCapture\n");

			priv.cc = &pcm->capture;
			err = parse_compound(soc_tplg, n, parse_pcm_cap_config,
				&priv);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}
#endif

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
			elem->type = PARSER_TYPE_DAPM_GRAPH;

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

	pcm_dai->size = sizeof(*pcm_dai);

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
	elem->type = PARSER_TYPE_PCM;
	pcm_dai->size = sizeof(pcm_dai);

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

/*
 * Parse compound
 */
static int parse_compound(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	int (*fcn)(struct soc_tplg_priv *, snd_config_t *, void *),
	void *private)
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

		if (strcmp(id, "SectionPCMConfig") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_config, NULL);
			if (err < 0)
				return err;
			continue;
		}
#if 0
		if (strcmp(id, "SectionPCMCapabilities") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_caps, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionPCM") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm, NULL);
			if (err < 0)
				return err;
			continue;
		}
#endif
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
#if 0
	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *elem;
	struct snd_soc_tplg_dapm_graph_elem *route;

	base = &soc_tplg->route_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, struct soc_tplg_elem, list);

		if (!elem->route || elem->type != PARSER_TYPE_DAPM_GRAPH) {
			tplg_error("Invalid route 's'\n", elem->id);
			return -EINVAL;
		}

		route = elem->route;
		tplg_dbg("\nCheck route: sink '%s', control '%s', source '%s'\n",
			route->sink, route->control, route->source);

		if (strlen(route->sink)
			&& !lookup_element(&soc_tplg->widget_list, route->sink,
			PARSER_TYPE_DAPM_WIDGET)
			&& !lookup_pcm_dai_stream(&soc_tplg->pcm_list, route->sink)) {
			tplg_error("Route: Undefined sink widget/stream '%s'\n",
				route->sink);
			return -EINVAL;
		}

		if (strlen(route->control)
			&& !lookup_element(&soc_tplg->control_list, route->control,
			PARSER_TYPE_MIXER)) {
			tplg_error("Route: Undefined mixer control '%s'\n",
				route->control);
			return -EINVAL;
		}

		if (strlen(route->source)
			&& !lookup_element(&soc_tplg->widget_list, route->source,
			PARSER_TYPE_DAPM_WIDGET)
			&& !lookup_pcm_dai_stream(&soc_tplg->pcm_list, route->source)) {
			tplg_error("Route: Undefined source widget/stream '%s'\n",
				route->source);
			return -EINVAL;
		}
	}
#endif
	return 0;
}

/* make sure that TLV data referenced by control is available */
static int check_referenced_tlv(struct soc_tplg_priv *soc_tplg,
				struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;

	tplg_dbg("\nCheck control tlv: '%s'\n", elem->id);

	base = &elem->ref_list;

	/* for each ref in this control elem */
	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, struct soc_tplg_ref, list);
		if (ref->id == NULL || ref->elem)
			continue;

		/* see if ref is a TLV */
		ref->elem = lookup_element(&soc_tplg->tlv_list,
			ref->id, PARSER_TYPE_TLV);
		if (!ref->elem) {
			tplg_error("Cannot find tlv '%s' referenced by"
				" control '%s'\n", ref->id, elem->id);
			return -EINVAL;
		}

		return 0;
	}

	return 0;
}

static int check_controls(struct soc_tplg_priv *soc_tplg)
{
	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *elem;
	int err;

	base = &soc_tplg->control_list;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);

		err = check_referenced_tlv(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	return 0;
}

static int check_referenced_controls(struct soc_tplg_priv *soc_tplg,
	struct soc_tplg_elem *elem)
{
	return 0;
}

static int check_widgets(struct soc_tplg_priv *soc_tplg)
{

	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *elem;
	int err;

	base = &soc_tplg->widget_list;
	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		if (!elem->widget|| elem->type != PARSER_TYPE_DAPM_WIDGET) {
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
		//goto out; // TODO fix integ checking
	}

	err = socfw_write_data(soc_tplg);
	if (err < 0) {
		tplg_error("Failed to write data %d\n", err);
		goto out;
	}

out:
	snd_config_delete(cfg);
	return err;
}

