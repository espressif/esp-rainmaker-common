/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file mutex.c
 * @brief FreeRTOS implementation of esp_rmaker_aws_sign_mutex_ops_t.
 *
 * @note Only esp_rmaker_aws_sign_port_install_default() references the table below.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static esp_rmaker_aws_sign_mutex_t esp_mutex_create(void)
{
    return (esp_rmaker_aws_sign_mutex_t)xSemaphoreCreateMutex();
}

static void esp_mutex_lock(esp_rmaker_aws_sign_mutex_t m)
{
    xSemaphoreTake((SemaphoreHandle_t)m, portMAX_DELAY);
}

static void esp_mutex_unlock(esp_rmaker_aws_sign_mutex_t m)
{
    xSemaphoreGive((SemaphoreHandle_t)m);
}

static void esp_mutex_destroy(esp_rmaker_aws_sign_mutex_t m)
{
    vSemaphoreDelete((SemaphoreHandle_t)m);
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_mutex_ops_t esp_rmaker_aws_sign_esp_mutex_ops = {
    .create = esp_mutex_create,
    .lock = esp_mutex_lock,
    .unlock = esp_mutex_unlock,
    .destroy = esp_mutex_destroy,
};
