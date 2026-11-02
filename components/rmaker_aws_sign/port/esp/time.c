/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file time.c
 * @brief libc implementation of esp_rmaker_aws_sign_time_ops_t.
 *
 * @note is_synced() is a plausibility threshold; an integrator with a real
 *       SNTP-state API should replace that one member.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include <time.h>
#include "sdkconfig.h"

static time_t esp_time_get(time_t *p_time)
{
    return time(p_time);
}

static bool esp_time_is_synced(void)
{
    return (int64_t)time(NULL) > CONFIG_ESP_RMAKER_AWS_SIGN_MIN_VALID_EPOCH;
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_time_ops_t esp_rmaker_aws_sign_esp_time_ops = {
    .get_time = esp_time_get,
    .is_synced = esp_time_is_synced,
};
