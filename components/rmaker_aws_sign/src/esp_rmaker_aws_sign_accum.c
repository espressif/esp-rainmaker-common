/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_accum.c
 * @brief The response sink both HTTP paths stream into.
 */

#include <string.h>
#include "esp_rmaker_aws_sign_internal.h"

#define ACCUM_MIN_CAP 512

void esp_rmaker_aws_sign_accum_init(esp_rmaker_aws_sign_accum_t *a, size_t limit)
{
    memset(a, 0, sizeof(*a));
    a->limit = limit;
}

/* Keeps the buffer, drops what it holds, so a retry starts from an empty body. */
void esp_rmaker_aws_sign_accum_reset(esp_rmaker_aws_sign_accum_t *a)
{
    a->len = 0;
    a->status = ESP_OK;
    a->got_response = false;
    if (a->buf) {
        a->buf[0] = '\0';
    }
}

/* Wiped, because the body may be a credential response. */
void esp_rmaker_aws_sign_accum_free(esp_rmaker_aws_sign_accum_t *a)
{
    if (a->buf) {
        aws_zeroize(a->buf, a->len);
    }
    AWS_FREE(a->buf);
    a->buf = NULL;
    a->len = 0;
    a->cap = 0;
}

/* Room for @c need bytes plus the terminator: exactly that much when the size
 * is known up front, otherwise doubling from ACCUM_MIN_CAP. */
static esp_err_t accum_reserve(esp_rmaker_aws_sign_accum_t *a, size_t need, bool exact)
{
    if (need > a->limit) {
        a->status = ESP_ERR_INVALID_SIZE;
        return a->status;
    }
    if (need + 1 <= a->cap) {
        return ESP_OK;
    }
    size_t cap = need + 1;
    if (!exact) {
        cap = a->cap ? a->cap : ACCUM_MIN_CAP;
        while (cap < need + 1) {
            cap *= 2;
        }
        if (cap > a->limit + 1) {
            cap = a->limit + 1;
        }
    }
    uint8_t *buf = AWS_MALLOC(cap);
    if (!buf) {
        a->status = ESP_ERR_NO_MEM;
        return a->status;
    }
    if (a->len) {
        memcpy(buf, a->buf, a->len);
        aws_zeroize(a->buf, a->len);
    }
    AWS_FREE(a->buf);
    a->buf = buf;
    a->cap = cap;
    return ESP_OK;
}

static int accum_hint(void *ctx, size_t content_length)
{
    esp_rmaker_aws_sign_accum_t *a = ctx;

    a->got_response = true;
    if (!content_length) {
        return 0;                       /* chunked or undeclared: grow as it arrives */
    }
    return accum_reserve(a, content_length, true) == ESP_OK ? 0 : -1;
}

static int accum_sink(void *ctx, const uint8_t *data, size_t len)
{
    esp_rmaker_aws_sign_accum_t *a = ctx;

    a->got_response = true;
    if (accum_reserve(a, a->len + len, false) != ESP_OK) {
        return 0;                       /* 0 aborts the transfer; status says why */
    }
    memcpy(a->buf + a->len, data, len);
    a->len += len;
    a->buf[a->len] = '\0';
    return (int)len;
}

esp_rmaker_aws_sign_http_receiver_t
esp_rmaker_aws_sign_accum_receiver(esp_rmaker_aws_sign_accum_t *a)
{
    return (esp_rmaker_aws_sign_http_receiver_t) {
        .hint = accum_hint, .sink = accum_sink, .ctx = a
    };
}
