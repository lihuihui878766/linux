/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Ventana Micro Systems Inc.
 */

#ifndef _RPMI_H
#define _RPMI_H

#include <linux/types.h>

#define RPMI_SRVGRP_CLOCK	0x00007

enum rpmi_clock_service_id {
	RPMI_CLK_SRV_ENABLE_NOTIFICATION = 0x01,
	RPMI_CLK_SRV_GET_SYSTEM_CLOCKS = 0x02,
	RPMI_CLK_SRV_GET_ATTRIBUTES = 0x03,
	RPMI_CLK_SRV_GET_SUPPORTED_RATES = 0x04,
	RPMI_CLK_SRV_SET_CONFIG = 0x05,
	RPMI_CLK_SRV_GET_CONFIG = 0x06,
	RPMI_CLK_SRV_SET_RATE = 0x07,
	RPMI_CLK_SRV_GET_RATE = 0x08,
	RPMI_CLK_SRV_ID_MAX_COUNT,
};

#endif
