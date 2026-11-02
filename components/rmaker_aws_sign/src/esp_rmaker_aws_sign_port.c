/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_port.c
 * @brief Holds the installed port and validates it at install time.
 *
 * @note Must not name port/esp: only esp_rmaker_aws_sign_default.c may.
 */

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "esp_rmaker_aws_sign_internal.h"

static const char *TAG = "esp_rmaker_aws_sign_port";

esp_rmaker_aws_sign_port_config_t g_esp_rmaker_aws_sign_port;

enum { PORT_NONE, PORT_INSTALLING, PORT_INSTALLED };

/* Atomic, not a mutex: the mutex ops arrive with the port. */
static atomic_int s_port_state;

bool esp_rmaker_aws_sign_port_is_installed(void)
{
    return atomic_load_explicit(&s_port_state, memory_order_acquire) == PORT_INSTALLED;
}

/* Field-wise rather than memcmp: struct padding is unspecified even for a
 * designated initializer, so two identical configs can differ byte-wise. */
static bool port_equal(const esp_rmaker_aws_sign_port_config_t *a,
                       const esp_rmaker_aws_sign_port_config_t *b)
{
    return a->mem.malloc == b->mem.malloc
           && a->mem.calloc == b->mem.calloc
           && a->mem.free == b->mem.free
           && a->crypto.init == b->crypto.init
           && a->crypto.sha256_init == b->crypto.sha256_init
           && a->crypto.sha256_update == b->crypto.sha256_update
           && a->crypto.sha256_finish == b->crypto.sha256_finish
           && a->crypto.sha256_abort == b->crypto.sha256_abort
           && a->crypto.hmac_sha256 == b->crypto.hmac_sha256
           && a->time.get_time == b->time.get_time
           && a->time.is_synced == b->time.is_synced
           && a->mutex.create == b->mutex.create
           && a->mutex.lock == b->mutex.lock
           && a->mutex.unlock == b->mutex.unlock
           && a->mutex.destroy == b->mutex.destroy
           && a->http.open == b->http.open
           && a->http.set_url == b->http.set_url
           && a->http.set_method == b->http.set_method
           && a->http.set_header == b->http.set_header
           && a->http.perform == b->http.perform
           && a->http.status_code == b->http.status_code
           && a->http.close == b->http.close
           && a->json.read_strs == b->json.read_strs
           && a->log == b->log;
}

static esp_err_t port_prepare(const esp_rmaker_aws_sign_port_config_t *port)
{
    if (port->mem.malloc == NULL || port->mem.calloc == NULL || port->mem.free == NULL) {
        AWS_LOGE(TAG, "Port is missing one or more memory operations");
        return ESP_ERR_INVALID_ARG;
    }
    /* Required outright: nothing here works without a digest. */
    if (port->crypto.sha256_init == NULL || port->crypto.sha256_update == NULL
            || port->crypto.sha256_finish == NULL || port->crypto.sha256_abort == NULL
            || port->crypto.hmac_sha256 == NULL) {
        AWS_LOGE(TAG, "Port is missing one or more crypto operations");
        return ESP_ERR_INVALID_ARG;
    }
    if (port->time.get_time == NULL) {
        AWS_LOGE(TAG, "Port is missing time.get_time");
        return ESP_ERR_INVALID_ARG;
    }

    /* All-or-nothing: a partial table would fail at some later point instead. */
    const esp_rmaker_aws_sign_mutex_ops_t *mtx = &port->mutex;
    int mutex_set = (mtx->create != NULL) + (mtx->lock != NULL) + (mtx->unlock != NULL)
                    + (mtx->destroy != NULL);
    if (mutex_set != 0 && mutex_set != 4) {
        AWS_LOGE(TAG, "Port supplies an incomplete set of mutex operations");
        return ESP_ERR_INVALID_ARG;
    }

    const esp_rmaker_aws_sign_http_ops_t *http = &port->http;
    int http_set = (http->open != NULL) + (http->set_url != NULL) + (http->set_method != NULL)
                   + (http->set_header != NULL) + (http->perform != NULL)
                   + (http->status_code != NULL) + (http->close != NULL);
    if (http_set != 0 && http_set != 7) {
        AWS_LOGE(TAG, "Port supplies an incomplete set of HTTP operations");
        return ESP_ERR_INVALID_ARG;
    }
    /* mutex and json serve the credential fetch, so HTTP without them is
     * misconfigured rather than minimal. */
    if (http_set == 7 && (mutex_set != 4 || port->json.read_strs == NULL)) {
        AWS_LOGE(TAG, "Port supplies HTTP operations without mutex and JSON operations");
        return ESP_ERR_INVALID_ARG;
    }
    /* Here, before any task can sign, because a backend init may not be thread-safe. */
    if (port->crypto.init && port->crypto.init() != ESP_OK) {
        AWS_LOGE(TAG, "Crypto backend init failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t esp_rmaker_aws_sign_port_install(const esp_rmaker_aws_sign_port_config_t *port)
{
    if (port == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    int state = PORT_NONE;
    if (!atomic_compare_exchange_strong_explicit(&s_port_state, &state, PORT_INSTALLING,
                                                 memory_order_acquire, memory_order_acquire)) {
        /* No wait: a higher-priority task that spins would starve the installer. */
        if (state == PORT_INSTALLING) {
            return ESP_ERR_NOT_FINISHED;
        }
        /* Re-installing the same port is harmless; swapping one in is not,
         * since the table is read without locking everywhere else. */
        if (port_equal(&g_esp_rmaker_aws_sign_port, port)) {
            return ESP_OK;
        }
        AWS_LOGE(TAG, "A different port is already installed; cannot replace it");
        return ESP_ERR_INVALID_STATE;
    }

    /* Only this install writes the table now; the log goes first so validation can report. */
    g_esp_rmaker_aws_sign_port.log = port->log;
    esp_err_t err = port_prepare(port);
    if (err != ESP_OK) {
        memset(&g_esp_rmaker_aws_sign_port, 0, sizeof(g_esp_rmaker_aws_sign_port));
        atomic_store_explicit(&s_port_state, PORT_NONE, memory_order_release);
        return err;
    }
    g_esp_rmaker_aws_sign_port = *port;
    atomic_store_explicit(&s_port_state, PORT_INSTALLED, memory_order_release);
    return ESP_OK;
}

void esp_rmaker_aws_sign_port_uninstall(void)
{
    memset(&g_esp_rmaker_aws_sign_port, 0, sizeof(g_esp_rmaker_aws_sign_port));
    atomic_store_explicit(&s_port_state, PORT_NONE, memory_order_release);
}

/* Small on purpose: messages truncate rather than grow the stack. */
#define ESP_RMAKER_AWS_SIGN_LOG_BUF_LEN 160

void esp_rmaker_aws_sign_log(esp_rmaker_aws_sign_log_level_t level, const char *tag,
                             const char *format, ...)
{
    esp_rmaker_aws_sign_log_fn_t log = g_esp_rmaker_aws_sign_port.log;
    if (log == NULL) {
        return;
    }
    /* Formatted here rather than handing the va_list to the port, which could
     * double-end it. */
    char message[ESP_RMAKER_AWS_SIGN_LOG_BUF_LEN];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    log(level, tag, message);
}
