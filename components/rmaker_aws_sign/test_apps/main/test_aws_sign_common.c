/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "unity_test_utils_memory.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"
#include "test_aws_sign.h"

void test_aws_sign_install_signer_port(void)
{
    /* Re-installing an identical port is a no-op, so every test may call this. */
    esp_rmaker_aws_sign_port_config_t port = {
        .mem = esp_rmaker_aws_sign_esp_mem_ops,
        .crypto = esp_rmaker_aws_sign_esp_crypto_ops,
        .time = esp_rmaker_aws_sign_esp_time_ops,
        .json = esp_rmaker_aws_sign_esp_json_ops,
        .log = esp_rmaker_aws_sign_esp_log,
    };
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
}

void test_aws_sign_assert_digest(const char *expect_hex, const uint8_t digest[32])
{
    char hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
    TEST_ASSERT_EQUAL_STRING(expect_hex, hex);
}

void test_aws_sign_heap_record(void)
{
    unity_utils_record_free_mem();
}

void test_aws_sign_heap_check(void)
{
    unity_utils_evaluate_leaks_direct(0);
}
