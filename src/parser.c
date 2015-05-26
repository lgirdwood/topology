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

void tplg_error(const char *fmt, ...)
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
	free_ref_list(&elem->ref_list);

	/* free struct snd_soc_tplg_ object,
	 * the union pointers share the same address
	 */
	if(elem->mixer_ctrl)
		free(elem->mixer_ctrl);

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
	INIT_LIST_HEAD(&soc_tplg->widget_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_list);
	INIT_LIST_HEAD(&soc_tplg->be_list);
	INIT_LIST_HEAD(&soc_tplg->cc_list);
	INIT_LIST_HEAD(&soc_tplg->route_list);
	INIT_LIST_HEAD(&soc_tplg->pdata_list);
	INIT_LIST_HEAD(&soc_tplg->text_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_config_list);
	INIT_LIST_HEAD(&soc_tplg->pcm_caps_list);
	INIT_LIST_HEAD(&soc_tplg->mixer_list);
	INIT_LIST_HEAD(&soc_tplg->enum_list);
	INIT_LIST_HEAD(&soc_tplg->bytes_ext_list);
 
	return soc_tplg;
}

void socfw_free(struct soc_tplg_priv *soc_tplg)
{
	close(soc_tplg->out_fd);

	free_elem_list(&soc_tplg->tlv_list);
	free_elem_list(&soc_tplg->widget_list);
	free_elem_list(&soc_tplg->pcm_list);
	free_elem_list(&soc_tplg->be_list);
	free_elem_list(&soc_tplg->cc_list);
	free_elem_list(&soc_tplg->route_list);
	free_elem_list(&soc_tplg->pdata_list);
	free_elem_list(&soc_tplg->text_list);
	free_elem_list(&soc_tplg->pcm_config_list);
	free_elem_list(&soc_tplg->pcm_caps_list);
	free_elem_list(&soc_tplg->mixer_list);
	free_elem_list(&soc_tplg->enum_list);
	free_elem_list(&soc_tplg->bytes_ext_list);

	free(soc_tplg);
}

static struct soc_tplg_elem *lookup_element(struct list_head *base,
				const char* id,
				u32 type)
{
	struct list_head *pos, *npos;
	struct soc_tplg_elem *elem;

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);

		if (!strcmp(elem->id, id) && elem->type == type)
			return elem;
	}

	return NULL;
}

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
		if (pcm_dai && (!strcmp(pcm_dai->capconf[0].caps.name, id)
			|| !strcmp(pcm_dai->capconf[1].caps.name, id)))
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

	/* cant find string name in our table so we use its ID number */
	return atoi(c);
}

static struct soc_tplg_elem* create_elem_common(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, enum parser_type type)
{
	struct soc_tplg_elem *elem;
	const char *id;
	int obj_size = 0;
	void *obj;

	elem = elem_new();
	if (!elem)
		return NULL;

	snd_config_get_id(cfg, &id);
	strncpy(elem->id, id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	switch (type) {
	case PARSER_TYPE_DATA:
		list_add_tail(&elem->list, &soc_tplg->pdata_list);
		break;
		
	case PARSER_TYPE_TEXT:
		list_add_tail(&elem->list, &soc_tplg->text_list);
		break;
	
	case PARSER_TYPE_TLV:
		list_add_tail(&elem->list, &soc_tplg->tlv_list);
		elem->size = sizeof(struct snd_soc_tplg_ctl_tlv);
		break;

	case PARSER_TYPE_BYTES:
		list_add_tail(&elem->list, &soc_tplg->bytes_ext_list);
		obj_size = sizeof(struct snd_soc_tplg_bytes_control);
		break;

	case PARSER_TYPE_ENUM:
		list_add_tail(&elem->list, &soc_tplg->enum_list);
		obj_size = sizeof(struct snd_soc_tplg_enum_control);
		break;
		
	case SND_SOC_TPLG_TYPE_MIXER:
		list_add_tail(&elem->list, &soc_tplg->mixer_list);
		obj_size = sizeof(struct snd_soc_tplg_mixer_control);
		break;
		
	case PARSER_TYPE_DAPM_WIDGET:
		list_add_tail(&elem->list, &soc_tplg->widget_list);
		obj_size = sizeof(struct snd_soc_tplg_dapm_widget);
		break;
		
	case PARSER_TYPE_STREAM_CONFIG:
		list_add_tail(&elem->list, &soc_tplg->pcm_config_list);
		obj_size = sizeof(struct snd_soc_tplg_stream_config);
		break;
		
	case PARSER_TYPE_STREAM_CAPS:
		list_add_tail(&elem->list, &soc_tplg->pcm_caps_list);
		obj_size = sizeof(struct snd_soc_tplg_stream_caps);
		break;
		
	case PARSER_TYPE_PCM:
		list_add_tail(&elem->list, &soc_tplg->pcm_list);
		obj_size = sizeof(struct snd_soc_tplg_pcm_dai);
		break;
	
	case PARSER_TYPE_BE:
		list_add_tail(&elem->list, &soc_tplg->be_list);
		obj_size = sizeof(struct snd_soc_tplg_pcm_dai);
		break;
		
	case PARSER_TYPE_CC:
		list_add_tail(&elem->list, &soc_tplg->cc_list);
		obj_size = sizeof(struct snd_soc_tplg_pcm_dai);
		break;
		
	default:
		free(elem);
		return NULL;
	}

	if (obj_size > 0) {
		obj = calloc(1, obj_size);
		if (obj == NULL) {
			free(elem);
			return NULL;
		}
		
		elem->obj = obj;
		elem->size = obj_size;
	}

	elem->type = type;
	return elem;	
}

/* Get Private data from a file. */
static int parse_data_file(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem)
{
	struct snd_soc_tplg_private *priv = NULL;
	const char *value = NULL;
	FILE *fp;
	int size;
	size_t bytes_read;
	int err = 0;

	tplg_dbg("data DataFile: %s\n", elem->id);

	if (snd_config_get_string(cfg, &value) < 0)
		return -EINVAL;

	fp = fopen(value, "r");
	if (fp == NULL) {
		tplg_error("Invalid Data file path '%s'\n", value);
		err = -errno;
		goto __err;
	}

	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	if (size <= 0) {
		tplg_error("Invalid Data file size %d\n", size);
		err = -EINVAL;
		goto __err;
	}

	priv = calloc(1, sizeof(*priv) + size);
	if (!priv) {
		err = -ENOMEM;
		goto __err;
	}

	bytes_read = fread(&priv->data, 1, size, fp);
	if (bytes_read != size) {
		err = -errno;
		goto __err;
	}

	elem->data = priv;
	priv->size = size;
	elem->size = sizeof(*priv) + size;
	return 0;

__err:
	if (priv)
		free(priv);
	return err;
}

static void dump_priv_data(struct soc_tplg_elem *elem)
{
	struct snd_soc_tplg_private *priv = elem->data;
	unsigned char *p = (unsigned char *)priv->data;
	int i, j = 0;

	tplg_dbg(" elem size = %d, priv data size = %d\n", elem->size, priv->size);

	for (i = 0; i < priv->size; i++) {
		if (j++ % 8 == 0)
			tplg_dbg("\n");

		tplg_dbg(" 0x%x", *p++);
	}

	tplg_dbg("\n\n");
}

static int get_hex_num(const char *str)
{
	char *tmp, *s = NULL;
	int i = 0;

	tmp = strdup(str);
	if (tmp == NULL)
		return -ENOMEM;

	s = strtok(tmp, ",");
	while (s != NULL) {
		s = strtok(NULL, ",");
		i++;
	}

	free(tmp);
	return i;
}

static int write_hex(char *buf, char *str, int width)
{
	long val;
	void *p = &val;
	
        errno = 0;
	val = strtol(str, NULL, 16);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
		|| (errno != 0 && val == 0)) {
		return -EINVAL;
        }

	switch (width) {
	case 1:
		*(unsigned char *)buf = *(unsigned char *)p;
		break;
	case 2:
		*(unsigned short *)buf = *(unsigned short *)p;
		break;
	case 4:
		*(unsigned int *)buf = *(unsigned int *)p;
		break;
	default:
		return -EINVAL;
	}
	
	return 0;
}

static int copy_data_hex(char *data, int off, const char *str, int width)
{
	char *tmp, *s = NULL, *p = data;
	int ret;

	tmp = strdup(str);
	if (tmp == NULL)
		return -ENOMEM;

	p += off;
	s = strtok(tmp, ",");

	while (s != NULL) {
		ret = write_hex(p, s, width);
		if (ret < 0) {
			free(tmp);
			return ret;
		}

		s = strtok(NULL, ",");
		p += width;
	}

	free(tmp);
	return 0;
}

static int parse_data_hex(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	struct soc_tplg_elem *elem, int width)
{
	struct snd_soc_tplg_private *priv;
	const char *value = NULL;
	int size, esize, off, num;
	int ret;

	tplg_dbg(" data: %s\n", elem->id);

	if (snd_config_get_string(cfg, &value) < 0)
		return -EINVAL;

	num = get_hex_num(value);
	size = num * width;
	priv = elem->data;

	if (priv != NULL) {
		off = priv->size;
		esize = elem->size + size;
		priv = realloc(priv, esize);
	} else {
		off = 0;
		esize = sizeof(*priv) + size;
		priv = calloc(1, esize);
	}

	if (!priv)
		return -ENOMEM;	
	
	elem->data = priv;
	priv->size += size;
	elem->size = esize;

	ret = copy_data_hex(priv->data, off, value, width);
	
	dump_priv_data(elem);
	return ret;
}


/* Parse Private data.
 *
 * Object private data
 *
 * SectionData."data name" {
 * 
 *		DataFile <filename>
 *		bytes
 *		shorts
 *		words
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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_DATA);
	if (!elem)
		return -ENOMEM;

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

		if (strcmp(id, "bytes") == 0) {
			err = parse_data_hex(soc_tplg, n, elem, 1);
			if (err < 0) {
				tplg_error("error: failed to parse data bytes");
				return err;
			}
			continue;
		}

		if (strcmp(id, "shorts") == 0) {
			err = parse_data_hex(soc_tplg, n, elem, 2);
			if (err < 0) {
				tplg_error("error: failed to parse data shorts");
				return err;
			}
			continue;
		}

		if (strcmp(id, "words") == 0) {
			err = parse_data_hex(soc_tplg, n, elem, 4);
			if (err < 0) {
				tplg_error("error: failed to parse data words");
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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_TEXT);
	if (!elem)
		return -ENOMEM;

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

		if (strcmp(id, "info") == 0)
			hdr->ops.info = lookup_ops(value);
		else if (strcmp(id, "put") == 0)
			hdr->ops.put = lookup_ops(value);
		else if (strcmp(id, "get") == 0)
			hdr->ops.get = lookup_ops(value);

		tplg_dbg("\t\t%s = %s\n", id, value);
	}

	return 0;
}

/*
 * Parse TLV of DBScale type.
 *
 * Parse DBScale describing min, step, mute in DB.
 *
 * scale [
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

	tplg_dbg(" scale: %s\n", elem->id);

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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_TLV);
	if (!elem)
		return -ENOMEM;

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
 *	max "255"
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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_BYTES);
	if (!elem)
		return -ENOMEM;

	be = elem->bytes_ext;
	be->size = elem->size;
	strncpy(be->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	be->hdr.type =  SND_SOC_TPLG_TYPE_BYTES;
	
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

		if (strcmp(id, "max") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			be->max = atoi(val);
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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_ENUM);
	if (!elem)
		return -ENOMEM;

	/* init new mixer */
	ec = elem->enum_ctrl;
	strncpy(ec->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	ec->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;
	ec->hdr.type =  SND_SOC_TPLG_TYPE_ENUM;
	ec->size = elem->size;

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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_MIXER);
	if (!elem)
		return -ENOMEM;

	/* init new mixer */
	mc = elem->mixer_ctrl;
	strncpy(mc->hdr.name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);	
	mc->hdr.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |
		SNDRV_CTL_ELEM_ACCESS_READWRITE;
	mc->hdr.type =  SND_SOC_TPLG_TYPE_MIXER;
	mc->size = elem->size;

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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_DAPM_WIDGET);
	if (!elem)
		return -ENOMEM;

	widget = elem->widget;
	strncpy(widget->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
	widget->size = elem->size;

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

		if (strcmp(id, "shift") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			widget->shift = atoi(val);
			tplg_dbg("\t%s: %d\n", id, widget->shift);
			continue;
		}

		if (strcmp(id, "invert") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			widget->invert = atoi(val);
			tplg_dbg("\t%s: %d\n", id, widget->invert);
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

static __le64 lookup_pcm_format(const char *c)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pcm_format_map); i++) {
		if (strcmp(pcm_format_map[i].name, c) == 0)
			return pcm_format_map[i].id;
	}

	return -EINVAL;
}

static int parse_stream_cfg(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct snd_soc_tplg_stream_config *sc = private;
	struct snd_soc_tplg_stream *stream;
	const char *id, *val;
	__le64 format;

	snd_config_get_id(cfg, &id);

	if (strcmp(id, "playback") == 0)
		stream = &sc->playback;
	else if (strcmp(id, "capture") == 0)
		stream = &sc->capture;
	else
		return -EINVAL;

	tplg_dbg("\t%s:\n", id);

	stream->size = sizeof(*stream);

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		if (snd_config_get_id(n, &id) < 0)
			return -EINVAL;

		if (snd_config_get_string(n, &val) < 0)
			return -EINVAL;

		if (strcmp(id, "format") == 0) {
			format = lookup_pcm_format(val);
			if (format < 0) {
				tplg_error("Unsupported stream format %s\n",
					val);
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
	}

	return 0;
}

/* Parse pcm configuration
 *
 * SectionPCMConfig."PCM config name" {
 *
 *	config."playback" {
 *		format
 *		rate
 *		channels
 *		tdm_slot
 *	}
 *
 *	config."capture" {
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

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_STREAM_CONFIG);
	if (!elem)
		return -ENOMEM;

	sc = elem->stream_cfg;
	sc->size = elem->size;

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

		if (strcmp(id, "config") == 0) {
			err = parse_compound(soc_tplg, n, parse_stream_cfg,
				sc);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}

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

/* Parse pcm Capabilities
 *
 * SectionPCMCapabilities." PCM capabilities name" {
 *
 *	formats "S24_LE,S16_LE"
 *	rate_min "48000"
 *	rate_max "48000"
 *	channels_min "2"
 *	channels_max "2"
 * } 
 */
static int parse_pcm_caps(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_stream_caps *sc;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val;
	char *s;
	int err;

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_STREAM_CAPS);
	if (!elem)
		return -ENOMEM;

	sc = elem->stream_caps;
	sc->size = elem->size;
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

		if (snd_config_get_string(n, &val) < 0)
			return -EINVAL;

		if (strcmp(id, "formats") == 0) {
			s = strdup(val);
			if (s == NULL)
				return -ENOMEM;

			err = split_format(sc, s);
			free(s);		

			if (err < 0)
				return err;

			tplg_dbg("\t\t%s: %s\n", id, val);
		} else if (strcmp(id, "rate_min") == 0) {
			sc->rate_min = atoi(val);
			tplg_dbg("\t\t%s: %d\n", id, sc->rate_min);
		} else if (strcmp(id, "rate_max") == 0) {
			sc->rate_max = atoi(val);
			tplg_dbg("\t\t%s: %d\n", id, sc->rate_max);
		} else if (strcmp(id, "channels_min") == 0) {
			sc->channels_min = atoi(val);
			tplg_dbg("\t\t%s: %d\n", id, sc->channels_min);
		} else if (strcmp(id, "channels_max") == 0) {
			sc->channels_max = atoi(val);
			tplg_dbg("\t\t%s: %d\n", id, sc->channels_max);
		}
	}

	return 0;	
}

static int parse_pcm_cfg(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	struct snd_soc_tplg_pcm_cfg_caps *capconf = private;
	struct snd_soc_tplg_stream_config *configs = capconf->configs;
	__le32 *num_configs = &capconf->num_configs;
	const char *value;

	if (*num_configs == SND_SOC_TPLG_STREAM_CONFIG_MAX)
		return -EINVAL;
	
	if (snd_config_get_string(cfg, &value) < 0)
		return EINVAL;

	strncpy(configs[*num_configs].name, value,
		SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	*num_configs += 1;

	tplg_dbg("\t\t\t%s\n", value);

	return 0;
}

/* Parse the cap and config of a pcm.
 *
 * pcm."name" {
 *
 *		capabilities "System playback"
 *
 *		configs [
 *			"PCM 48k Stereo 24bit"
 *			"PCM 48k Stereo 16bit"
 *		]
 * }
 */
static int parse_pcm_cap_cfg(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg,
	void *private)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct soc_tplg_elem *elem = private;
	struct snd_soc_tplg_pcm_dai *pcm_dai;
	const char *id, *value;
	int err, stream;

	if (elem->type == PARSER_TYPE_PCM)
		pcm_dai = elem->pcm;
	else if (elem->type == PARSER_TYPE_BE)
		pcm_dai = elem->be;
	else if (elem->type == PARSER_TYPE_CC)
		pcm_dai = elem->cc;
	else
		return -EINVAL;

	snd_config_get_id(cfg, &id);

	tplg_dbg("\t%s:\n", id);
	
	if (strcmp(id, "playback") == 0)
		stream = SND_SOC_TPLG_STREAM_PLAYBACK;
	else if (strcmp(id, "capture") == 0)
		stream = SND_SOC_TPLG_STREAM_CAPTURE;
	else
		return -EINVAL;

	snd_config_for_each(i, next, cfg) {

		n = snd_config_iterator_entry(i);

		/* get id */
		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "capabilities") == 0) {
			if (snd_config_get_string(n, &value) < 0)
				continue;

			strncpy(pcm_dai->capconf[stream].caps.name, value,
				SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

			tplg_dbg("\t\t%s\n\t\t\t%s\n", id, value);
			continue;
		}

		if (strcmp(id, "configs") == 0) {
			tplg_dbg("\t\tconfigs:\n");
			err = parse_compound(soc_tplg, n, parse_pcm_cfg,
				&pcm_dai->capconf[stream]);
			if (err < 0)
				return err;
			continue;			
		}
	}

	return 0;
}

/* Parse pcm
 *
 * SectionPCM."System Pin" {
 *
 *	index "1"
 *
 *	# used for binding to the PCM
 *	ID "0"
 *
 *	pcm."playback" {
 *		capabilities "System Playback"
 *		config "PCM 48k Stereo 24bit"
 *		config "PCM 48k Stereo 16bit"
 *	}
 *
 *	pcm."capture" {
 *		capabilities "Analog Capture"
 *		config "PCM 48k Stereo 24bit"
 *		config "PCM 48k Stereo 16bit"
 *		config "PCM 48k 2P/4C 16bit"
 *	}
 * }
 */
static int parse_pcm(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_pcm_dai *pcm_dai;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_PCM);
	if (!elem)
		return -ENOMEM;

	pcm_dai = elem->pcm;
	pcm_dai->size = elem->size;
	strncpy(pcm_dai->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

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

			elem->index = atoi(val);
			tplg_dbg("\t%s: %d\n", id, elem->index);
			continue;
		}

		if (strcmp(id, "ID") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			pcm_dai->id = atoi(val);
			tplg_dbg("\t%s: %d\n", id, pcm_dai->id);
			continue;
		}

		if (strcmp(id, "pcm") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_cap_cfg,
				elem);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}

/* Parse be
 *
 * SectionBE."SSP0-Codec" {
 *
 *	index "1"
 *
 *	# used for binding to the PCM
 *	ID "0"
 *
 *	be."playback" {
 *		capabilities "System Playback"
 *		config "PCM 48k Stereo 24bit"
 *		config "PCM 48k Stereo 16bit"
 *	}
 *
 *	be."capture" {
 *		capabilities "Analog Capture"
 *		config "PCM 48k Stereo 24bit"
 *		config "PCM 48k Stereo 16bit"
 *		config "PCM 48k 2P/4C 16bit"
 *	}
 * }
 */
static int parse_be(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_pcm_dai *pcm_dai;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_BE);
	if (!elem)
		return -ENOMEM;

	pcm_dai = elem->be;
	pcm_dai->size = elem->size;
	strncpy(pcm_dai->name, elem->id, SNDRV_CTL_ELEM_ID_NAME_MAXLEN);

	tplg_dbg(" BE: %s\n", elem->id);

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

		if (strcmp(id, "ID") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			pcm_dai->id = atoi(val);
			tplg_dbg("\t%s: %d\n", id, pcm_dai->id);
			continue;
		}

		if (strcmp(id, "be") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_cap_cfg,
				elem);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}

/* Parse cc
 *
 * SectionCC."FM-Codec" {
 *
 *	index "1"
 *
 *	# used for binding to the CC link
 *	ID "0"
 *
 *	# CC DAI link capabilities and supported configs
 *	cc."playback" {
 *
 *		capabilities "System playback"
 *
 *		configs [
 *			"PCM 48k Stereo 16bit"
 *		]
 *	}
 *
 *	cc."capture" {
 *
 *		capabilities "Analog capture"
 *
 *		configs [
 *			"PCM 48k Stereo 16bit"
 *		]
 *	} 
 * }
 */
static int parse_cc(struct soc_tplg_priv *soc_tplg,
	snd_config_t *cfg, void *private)
{
	struct snd_soc_tplg_pcm_dai *pcm_dai;
	struct soc_tplg_elem *elem;
	snd_config_iterator_t i, next;
	snd_config_t *n;
	const char *id, *val = NULL;
	int err;

	elem = create_elem_common(soc_tplg, cfg, PARSER_TYPE_CC);
	if (!elem)
		return -ENOMEM;

	pcm_dai = elem->cc;
	pcm_dai->size = elem->size;

	tplg_dbg(" CC: %s\n", elem->id);

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

		if (strcmp(id, "ID") == 0) {
			if (snd_config_get_string(n, &val) < 0)
				return -EINVAL;

			pcm_dai->id = atoi(val);
			tplg_dbg("\t%s: %d\n", id, pcm_dai->id);
			continue;
		}

		if (strcmp(id, "cc") == 0) {
			err = parse_compound(soc_tplg, n, parse_pcm_cap_cfg,
				elem);
			if (err < 0)
				return err;
			continue;
		}
	}

	return 0;
}

/* line is defined as '"source, control, sink"' */
static int parse_line(const char *text,
	struct snd_soc_tplg_dapm_graph_elem *line)
{
	char buf[1024];
	int len, i;
	const char *source = NULL, *sink = NULL, *control = NULL;

	strncpy(buf, text, 1024);

	len = strlen(buf);
	if (len <= 2) {
		tplg_error("error: invalid route \"%s\"\n", buf);
		return -EINVAL;
	}

	/* find first , */
	for (i = 1; i < len; i++) {
		if (buf[i] == ',')
			goto second;
	}
	tplg_error("error: invalid route \"%s\"\n", buf);
	return -EINVAL;

second:
	/* find second , */
	sink = buf;
	control = &buf[i + 2];
	buf[i] = 0;

	for (; i < len; i++) {
		if (buf[i] == ',')
			goto done;
	}

	tplg_error("error: invalid route \"%s\"\n", buf);
	return -EINVAL;

done:
	buf[i] = 0;
	source = &buf[i + 2];

	strcpy(line->source, source);
	strcpy(line->control, control);
	strcpy(line->sink, sink);
	return 0;
}

static int parse_routes(struct soc_tplg_priv *soc_tplg, snd_config_t *cfg)
{
	snd_config_iterator_t i, next;
	snd_config_t *n;
	struct soc_tplg_elem *elem;
	struct snd_soc_tplg_dapm_graph_elem *line = NULL;
	int err;

	snd_config_for_each(i, next, cfg) {
		const char *val;

		n = snd_config_iterator_entry(i);
		if (snd_config_get_string(n, &val) < 0)
			continue;

		elem = elem_new();
		if (!elem)
			return -ENOMEM;

		list_add_tail(&elem->list, &soc_tplg->route_list);
		strcpy(elem->id, "line");
		elem->type = PARSER_TYPE_DAPM_GRAPH;
		elem->size = sizeof(*line);

		line = calloc(1, sizeof(*line));
		if (!line)
			return -ENOMEM;

		elem->route = line;

		err = parse_line(val, line);
		if (err < 0)
			return err;

		tplg_dbg("route: sink '%s', control '%s', source '%s'\n",
				line->sink, line->control, line->source);
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

		if (strcmp(id, "lines") == 0) {
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

		if (strcmp(id, "SectionBE") == 0) {
			err = parse_compound(soc_tplg, n, parse_be, NULL);
			if (err < 0)
				return err;
			continue;
		}

		if (strcmp(id, "SectionCC") == 0) {
			err = parse_compound(soc_tplg, n, parse_cc, NULL);
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

		if (strlen(route->control)) {
			if (!lookup_element(&soc_tplg->mixer_list,
				route->control, PARSER_TYPE_MIXER) &&
			!lookup_element(&soc_tplg->enum_list,
				route->control, PARSER_TYPE_ENUM)) {
				tplg_error("Route: Undefined mixer/enum control '%s'\n",
					route->control);
			return -EINVAL;
			}
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

	return 0;
}

/* copy private data into the bytes extended control */
static int copy_data(struct soc_tplg_elem *elem,
	struct soc_tplg_elem *ref)
{
	struct snd_soc_tplg_private *priv;
	int priv_data_size;

	if (!ref)
		return -EINVAL;

	tplg_dbg("Data '%s' used by '%s'\n", ref->id, elem->id);
	priv_data_size = ref->data->size;

	switch (elem->type) {
		case PARSER_TYPE_MIXER:
			elem->mixer_ctrl = realloc(elem->mixer_ctrl, elem->size + priv_data_size);
			if (!elem->mixer_ctrl)
				return -ENOMEM;
			priv = &elem->mixer_ctrl->priv;
			break;

		case PARSER_TYPE_ENUM:
			elem->enum_ctrl = realloc(elem->enum_ctrl, elem->size + priv_data_size);
			if (!elem->enum_ctrl)
				return -ENOMEM;
			priv = &elem->enum_ctrl->priv;
			break;

		case PARSER_TYPE_BYTES:
			elem->bytes_ext = realloc(elem->bytes_ext, elem->size + priv_data_size);
			if (!elem->bytes_ext)
				return -ENOMEM;
			priv = &elem->bytes_ext->priv;
			break;


		case PARSER_TYPE_DAPM_WIDGET:
			elem->widget = realloc(elem->widget, elem->size + priv_data_size);
			if (!elem->widget)
				return -ENOMEM;
			priv = &elem->widget->priv;
			break;

		default:
			tplg_error("elem '%s': type %d shall not have private data\n", elem->id);
			return -EINVAL;
	}

	elem->size += priv_data_size;
	priv->size = priv_data_size;
	memcpy(priv->data, ref->data->data, priv_data_size);
	return 0;
}

/* copy referenced TLV to the mixer control */
static int copy_tlv(struct soc_tplg_elem *elem, struct soc_tplg_elem *ref)
{
	struct snd_soc_tplg_mixer_control *mixer_ctrl =  elem->mixer_ctrl;
	struct snd_soc_tplg_ctl_tlv *tlv = ref->tlv;

	tplg_dbg("TLV '%s' used by '%s\n", ref->id, elem->id);

	/* TLV has a fixed size */
	memcpy(&mixer_ctrl->tlv, tlv, sizeof(*tlv));
	return 0;
}

/* check referenced TLV for a mixer control */
static int check_mixer_control(struct soc_tplg_priv *soc_tplg,
				struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;
	int err = 0;

	base = &elem->ref_list;

	/* for each ref in this control elem */
	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, struct soc_tplg_ref, list);
		if (ref->id == NULL || ref->elem)
			continue;

		if (ref->type == PARSER_TYPE_TLV) {
			ref->elem = lookup_element(&soc_tplg->tlv_list,
						ref->id, PARSER_TYPE_TLV);
			if(ref->elem)
				 err = copy_tlv(elem, ref->elem);

		} else if (ref->type == PARSER_TYPE_DATA) {
			ref->elem = lookup_element(&soc_tplg->pdata_list,
						ref->id, PARSER_TYPE_DATA);
			 err = copy_data(elem, ref->elem);
		}

		if (!ref->elem) {
			tplg_error("Cannot find '%s' referenced by"
				" control '%s'\n", ref->id, elem->id);
			return -EINVAL;
		} else if (err < 0)
			return err;
	}

	return 0;
}

static void copy_enum_texts(struct soc_tplg_elem *enum_elem,
	struct soc_tplg_elem *ref_elem)
{
	struct snd_soc_tplg_enum_control *ec = enum_elem->enum_ctrl;

	memcpy(ec->texts, ref_elem->texts,
		SND_SOC_TPLG_NUM_TEXTS * SNDRV_CTL_ELEM_ID_NAME_MAXLEN);
}

/* check referenced text for a enum control */
static int check_enum_control(struct soc_tplg_priv *soc_tplg,
				struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;
	int err = 0;

	base = &elem->ref_list;

	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, struct soc_tplg_ref, list);
		if (ref->id == NULL || ref->elem)
			continue;

		if (ref->type == PARSER_TYPE_TEXT) {
			ref->elem = lookup_element(&soc_tplg->text_list,
						ref->id, PARSER_TYPE_TEXT);
			if (ref->elem)
				copy_enum_texts(elem, ref->elem);

		} else if (ref->type == PARSER_TYPE_DATA) {
			ref->elem = lookup_element(&soc_tplg->pdata_list,
						ref->id, PARSER_TYPE_DATA);
			err = copy_data(elem, ref->elem);
		}
		if (!ref->elem) {
			tplg_error("Cannot find '%s' referenced by"
				" control '%s'\n", ref->id, elem->id);
			return -EINVAL;
		} else if (err < 0)
			return err;
	}

	return 0;
}

/* check referenced private data for a byte control */
static int check_bytes_control(struct soc_tplg_priv *soc_tplg,
				struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;

	base = &elem->ref_list;
	list_for_each_safe(pos, npos, base) {
		ref = list_entry(pos, struct soc_tplg_ref, list);
		if (ref->id == NULL || ref->elem)
			continue;
		/* bytes control only reference one private data section */
		ref->elem = lookup_element(&soc_tplg->pdata_list,
			ref->id, PARSER_TYPE_DATA);
		if (!ref->elem) {
			tplg_error("Cannot find data '%s' referenced by"
				" control '%s'\n", ref->id, elem->id);
			return -EINVAL;
		}

		/* copy texts to enum elem */
		return copy_data(elem, ref->elem);
	}

	return 0;
}

static int check_controls(struct soc_tplg_priv *soc_tplg)
{
	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *elem;
	int err = 0;

	base = &soc_tplg->mixer_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, struct soc_tplg_elem, list);
		err = check_mixer_control(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	base = &soc_tplg->enum_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, struct soc_tplg_elem, list);
		err = check_enum_control(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	base = &soc_tplg->bytes_ext_list;
	list_for_each_safe(pos, npos, base) {
		elem = list_entry(pos, struct soc_tplg_elem, list);
		err = check_bytes_control(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	return 0;
}

/* move referenced controls to the widget */
static int move_control(struct soc_tplg_elem *elem, struct soc_tplg_elem *ref)
{
	struct snd_soc_tplg_dapm_widget *widget = elem->widget;
	struct snd_soc_tplg_mixer_control *mixer_ctrl = ref->mixer_ctrl;
	struct snd_soc_tplg_enum_control *enum_ctrl = ref->enum_ctrl;

	tplg_dbg("Control '%s' used by '%s'\n", ref->id, elem->id);
	tplg_dbg("\tparent size: %d + %d -> %d, priv size -> %d\n",
		elem->size, ref->size, elem->size + ref->size, widget->priv.size);

	widget = realloc(widget, elem->size + ref->size);
	if (!widget)
		return -ENOMEM;

	elem->widget = widget;

	/* copy new widget at the end */
	if (ref->type == PARSER_TYPE_MIXER)
		memcpy((void*)widget + elem->size, mixer_ctrl, ref->size);
	else if (ref->type == PARSER_TYPE_ENUM)
		memcpy((void*)widget + elem->size, enum_ctrl, ref->size);

	elem->size += ref->size;

	/* remove the control from global control list to avoid double output */
	list_del(&ref->list);
	elem_free(ref);
	return 0;
}

/* check referenced controls for a widget */
static int check_widget(struct soc_tplg_priv *soc_tplg,
	struct soc_tplg_elem *elem)
{
	struct soc_tplg_ref *ref;
	struct list_head *base, *pos, *npos;
	int err = 0;

	base = &elem->ref_list;

	/* for each ref in this control elem */
	list_for_each_safe(pos, npos, base) {

		ref = list_entry(pos, struct soc_tplg_ref, list);
		if (ref->id == NULL || ref->elem)
			continue;

		switch (ref->type) {
			case PARSER_TYPE_MIXER:
				ref->elem = lookup_element(&soc_tplg->mixer_list,
							ref->id, PARSER_TYPE_MIXER);
				if(ref->elem)
					err =  move_control(elem, ref->elem);
				break;

			case PARSER_TYPE_ENUM:
				ref->elem = lookup_element(&soc_tplg->enum_list,
							ref->id, PARSER_TYPE_ENUM);
				if(ref->elem)
					err =  move_control(elem, ref->elem);
				break;

			case PARSER_TYPE_DATA:
				ref->elem = lookup_element(&soc_tplg->pdata_list,
							ref->id, PARSER_TYPE_DATA);
				err =  copy_data(elem, ref->elem);
				break;
			default:
				break;
		}

		if (!ref->elem) {
			tplg_error("Cannot find control '%s' referenced by"
				" widget '%s'\n", ref->id, elem->id);
			return -EINVAL;
		} else  if (err < 0) 
			return err;
	}

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

		err = check_widget(soc_tplg, elem);
		if (err < 0)
			return err;
	}

	return 0;
}

/* copy referenced caps to the pcm */
static void copy_pcm_caps(const char *id, struct snd_soc_tplg_stream_caps *caps,
	struct soc_tplg_elem *ref_elem)
{
	struct snd_soc_tplg_stream_caps *ref_caps = ref_elem->stream_caps;

	tplg_dbg("Copy pcm caps (%d bytes) from '%s' to '%s' \n",
		sizeof(*caps), ref_elem->id, id);

	memcpy((void*)caps, ref_caps, sizeof(*caps));
}

/* copy referenced config to the pcm */
static void copy_pcm_config(const char *id,
	struct snd_soc_tplg_stream_config *cfg,
	struct soc_tplg_elem *ref_elem)
{
	struct snd_soc_tplg_stream_config *ref_cfg = ref_elem->stream_cfg;

	tplg_dbg("Copy pcm config (%d bytes) from '%s' to '%s' \n",
		sizeof(*cfg), ref_elem->id, id);

	memcpy((void*)cfg, ref_cfg, sizeof(*cfg));
}

/* check referenced config and caps for a pcm */
static int check_pcm_cfg_caps(struct soc_tplg_priv *soc_tplg,
	struct soc_tplg_elem *elem)
{
	struct soc_tplg_elem *ref_elem = NULL;
	struct snd_soc_tplg_pcm_cfg_caps *capconf;
	struct snd_soc_tplg_pcm_dai *pcm_dai;
	int i, j;

	switch (elem->type) {
	case PARSER_TYPE_PCM:
		pcm_dai = elem->pcm;
		break;	
	case PARSER_TYPE_BE:
		pcm_dai = elem->be;
		break;
	case PARSER_TYPE_CC:
		pcm_dai = elem->cc;
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < 2; i++) {
		capconf = &pcm_dai->capconf[i];

		ref_elem = lookup_element(&soc_tplg->pcm_caps_list,
			capconf->caps.name, PARSER_TYPE_STREAM_CAPS);

		if (ref_elem != NULL)
			copy_pcm_caps(elem->id, &capconf->caps, ref_elem);

		for (j = 0; j < capconf->num_configs; j++) {
			ref_elem = lookup_element(&soc_tplg->pcm_config_list,
				capconf->configs[j].name,
				PARSER_TYPE_STREAM_CONFIG);

			if (ref_elem != NULL)
				copy_pcm_config(elem->id,
					&capconf->configs[j],
					ref_elem);
		}
	}

	return 0;
}

static int check_pcm_dai(struct soc_tplg_priv *soc_tplg, int type)
{
	struct list_head *base, *pos, *npos;
	struct soc_tplg_elem *elem;
	int err = 0;

	switch (type) {
	case PARSER_TYPE_PCM:
		base = &soc_tplg->pcm_list;
		break;	
	case PARSER_TYPE_BE:
		base = &soc_tplg->be_list;
		break;
	case PARSER_TYPE_CC:
		base = &soc_tplg->cc_list;
		break;
	default:
		return -EINVAL;
	}

	list_for_each_safe(pos, npos, base) {

		elem = list_entry(pos, struct soc_tplg_elem, list);
		if (elem->type != type) {
			tplg_error("Invalid elem '%s'\n", elem->id);
			return -EINVAL;
		}

		err = check_pcm_cfg_caps(soc_tplg, elem);
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

	err = check_pcm_dai(soc_tplg, PARSER_TYPE_PCM);
	if (err <  0)
		return err;

	err = check_pcm_dai(soc_tplg, PARSER_TYPE_BE);
	if (err <  0)
		return err;

	err = check_pcm_dai(soc_tplg, PARSER_TYPE_CC);
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

	fprintf(stdout, "Loading config....\n");
	err = tplg_load_config(filename, &cfg);
	if (err < 0) {
		tplg_error("Failed to load topology file %s\n",
			filename);
		return err;
	}

	fprintf(stdout, "Parsing config....\n");
	err = tplg_parse_config(soc_tplg, cfg);
	if (err < 0) {
		tplg_error("Failed to parse topology\n");
		goto out;
	}

	fprintf(stdout, "Checking references....\n");
	err = tplg_check_integ(soc_tplg);
	if (err < 0) {
		tplg_error("Failed to check topology integrity\n");
		goto out;
	}

	fprintf(stdout, "Writing data\n");
	err = socfw_write_data(soc_tplg);
	if (err < 0) {
		tplg_error("Failed to write data %d\n", err);
		goto out;
	}

out:
	snd_config_delete(cfg);
	return err;
}

