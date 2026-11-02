/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file log.c
 * @brief esp_log implementation of esp_rmaker_aws_sign_log_fn_t.
 *
 * @note Only esp_rmaker_aws_sign_port_install_default() references this, so a build with its
 *       own port never pulls in esp_log.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include "esp_log.h"

/* The message arrives formatted, so this only picks the matching macro; "%s"
 * keeps the standard banner without reaching into esp_log internals. */
void esp_rmaker_aws_sign_esp_log(esp_rmaker_aws_sign_log_level_t level, const char *tag,
                                 const char *message)
{
    switch (level) {
    case ESP_RMAKER_AWS_SIGN_LOG_ERROR:
        ESP_LOGE(tag, "%s", message);
        break;
    case ESP_RMAKER_AWS_SIGN_LOG_WARN:
        ESP_LOGW(tag, "%s", message);
        break;
    case ESP_RMAKER_AWS_SIGN_LOG_INFO:
        ESP_LOGI(tag, "%s", message);
        break;
    case ESP_RMAKER_AWS_SIGN_LOG_DEBUG:
        ESP_LOGD(tag, "%s", message);
        break;
    default:
        ESP_LOGV(tag, "%s", message);
        break;
    }
}
