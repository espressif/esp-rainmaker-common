/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include "esp_rmaker_aws_sign.h"

/** @brief Compare two 64-bit values as 32-bit halves, since UNITY_SUPPORT_64 may be off. */
#define TEST_ASSERT_EQUAL_I64(expect, actual) do {                                          \
        int64_t expect_ = (int64_t)(expect), actual_ = (int64_t)(actual);                   \
        TEST_ASSERT_EQUAL_HEX32_MESSAGE((uint32_t)((uint64_t)expect_ >> 32),                \
                                        (uint32_t)((uint64_t)actual_ >> 32),                \
                                        "high word of a 64-bit value");                     \
        TEST_ASSERT_EQUAL_HEX32_MESSAGE((uint32_t)expect_, (uint32_t)actual_,               \
                                        "low word of a 64-bit value");                      \
    } while (0)

/** @brief Install mem + crypto + time + json + log, and no networking. */
void test_aws_sign_install_signer_port(void);

/** @brief Fail the current test unless @c digest matches @c expect_hex. */
void test_aws_sign_assert_digest(const char *expect_hex, const uint8_t digest[32]);

/** @brief Record the free heap, to be compared by test_aws_sign_heap_check(). */
void test_aws_sign_heap_record(void);

/** @brief Fail the current test if any heap was lost since the record. */
void test_aws_sign_heap_check(void);
