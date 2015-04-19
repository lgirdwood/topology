/*
 * linux/sound/socfw.h -- ALSA SoC Layer
 *
 * Copyright(c) 2014-2015 Intel Corporation
 * Copyright:	2012 Texas Instruments Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Simple file API to load FW, dynamic mixers, coefficients, DAPM graphs,
 * algorithms, equalisers, etc.
 */

#ifndef __SOC_TPLG_H
#define __SOC_TPLG_H

#ifdef __timespec_defined
#define _STRUCT_TIMESPEC
#endif

#ifdef __timeval_defined
#define _STRUCT_TIMEVAL
#endif

#include <linux/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include <sound/asound.h>
#include <uapi/sound/asoc.h>
#include <uapi/sound/tlv.h>

/* kernel typedefs */
typedef	uint32_t u32;
typedef	int32_t s32;
typedef	uint16_t u16;
typedef	int16_t s16;
typedef	uint8_t u8;
typedef	int8_t s8;

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

#endif
