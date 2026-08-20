/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_default.c
 * @brief Binds the ESP-IDF port to esp_rmaker_aws_sign_port_install_default().
 *
 * @warning Must hold this function and nothing else, and be the only file here
 *          naming the esp_*_ops tables, or port/esp stops being strippable.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

esp_err_t esp_rmaker_aws_sign_port_install_default(void)
{
    const esp_rmaker_aws_sign_port_config_t port = {
        .mem    = esp_rmaker_aws_sign_esp_mem_ops,
        .crypto = esp_rmaker_aws_sign_esp_crypto_ops,
        .time   = esp_rmaker_aws_sign_esp_time_ops,
        .mutex  = esp_rmaker_aws_sign_esp_mutex_ops,
        .http   = esp_rmaker_aws_sign_esp_http_ops,
        .json   = esp_rmaker_aws_sign_esp_json_ops,
        .log    = esp_rmaker_aws_sign_esp_log,
    };
    return esp_rmaker_aws_sign_port_install(&port);
}
