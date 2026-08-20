/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_esp_port.h
 * @brief The ESP-IDF implementations of the porting interface.
 *
 * @note Referencing a table links that one port file and its dependency, so an
 *       integrator can take the defaults and swap a single group. Inside the
 *       component only esp_rmaker_aws_sign_port_install_default() may name them.
 */

#pragma once

#include "esp_rmaker_aws_sign.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const esp_rmaker_aws_sign_mem_ops_t    esp_rmaker_aws_sign_esp_mem_ops;     /* port/esp/mem.c    */
extern const esp_rmaker_aws_sign_crypto_ops_t esp_rmaker_aws_sign_esp_crypto_ops;  /* port/esp/crypto.c */
extern const esp_rmaker_aws_sign_time_ops_t   esp_rmaker_aws_sign_esp_time_ops;    /* port/esp/time.c   */
extern const esp_rmaker_aws_sign_mutex_ops_t  esp_rmaker_aws_sign_esp_mutex_ops;   /* port/esp/mutex.c  */
extern const esp_rmaker_aws_sign_http_ops_t   esp_rmaker_aws_sign_esp_http_ops;    /* port/esp/http.c   */
extern const esp_rmaker_aws_sign_json_ops_t   esp_rmaker_aws_sign_esp_json_ops;    /* port/esp/json.c   */

void esp_rmaker_aws_sign_esp_log(esp_rmaker_aws_sign_log_level_t level, const char *tag,
                                 const char *message);

#ifdef __cplusplus
}
#endif
