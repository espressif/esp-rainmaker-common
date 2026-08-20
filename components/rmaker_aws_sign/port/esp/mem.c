/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file mem.c
 * @brief Heap implementation of esp_rmaker_aws_sign_mem_ops_t.
 *
 * @note Only esp_rmaker_aws_sign_port_install_default() references the table below.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include <stdlib.h>
#include "esp_heap_caps.h"

/* Prefer external RAM when the target has it configured, falling back to internal. */
#if ((CONFIG_SPIRAM || CONFIG_SPIRAM_SUPPORT) && \
        (CONFIG_SPIRAM_USE_CAPS_ALLOC || CONFIG_SPIRAM_USE_MALLOC))

static void *esp_mem_malloc(size_t size)
{
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM,
                                   MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);
}

static void *esp_mem_calloc(size_t num, size_t size)
{
    return heap_caps_calloc_prefer(num, size, 2, MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM,
                                   MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);
}

#else

static void *esp_mem_malloc(size_t size)
{
    return malloc(size);
}

static void *esp_mem_calloc(size_t num, size_t size)
{
    return calloc(num, size);
}

#endif

static void esp_mem_free(void *ptr)
{
    free(ptr);
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_mem_ops_t esp_rmaker_aws_sign_esp_mem_ops = {
    .malloc = esp_mem_malloc,
    .calloc = esp_mem_calloc,
    .free = esp_mem_free,
};
