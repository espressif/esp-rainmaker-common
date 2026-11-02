/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file http.c
 * @brief esp_http_client implementation of esp_rmaker_aws_sign_http_ops_t.
 *
 * @note The server CA is this port's choice, not the core's: it attaches the
 *       ESP x509 certificate bundle.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include <string.h>
#include "esp_http_client.h"
#include "sdkconfig.h"
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#else
#include "esp_log.h"
#endif

#define READ_CHUNK_LEN 512
/* esp_http_client cannot split one header, and a session token is up to ~1.5 KB. */
#define TX_BUF_LEN     CONFIG_ESP_RMAKER_AWS_SIGN_HTTP_TX_BUFFER_SIZE

static esp_http_client_method_t to_esp_method(esp_rmaker_aws_sign_http_method_t method)
{
    switch (method) {
    case ESP_RMAKER_AWS_SIGN_HTTP_POST:
        return HTTP_METHOD_POST;
    case ESP_RMAKER_AWS_SIGN_HTTP_PUT:
        return HTTP_METHOD_PUT;
    case ESP_RMAKER_AWS_SIGN_HTTP_DELETE:
        return HTTP_METHOD_DELETE;
    case ESP_RMAKER_AWS_SIGN_HTTP_PATCH:
        return HTTP_METHOD_PATCH;
    default:
        return HTTP_METHOD_GET;
    }
}

static esp_err_t esp_http_open(const esp_rmaker_aws_sign_http_config_t *cfg,
                               esp_rmaker_aws_sign_http_handle_t *out)
{
    if (!cfg || !cfg->url || !out) {
        return ESP_ERR_INVALID_ARG;
    }
#ifndef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    static bool s_no_ca_logged;
    if (!s_no_ca_logged) {
        ESP_LOGW("esp_rmaker_aws_sign_http", "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is off, so no "
                 "server CA is set and the TLS handshake fails");
        s_no_ca_logged = true;
    }
#endif
    esp_http_client_config_t esp_cfg = {
        .url = cfg->url,
        .method = to_esp_method(cfg->method),
        .timeout_ms = cfg->timeout_ms,
        .keep_alive_enable = cfg->keep_alive,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .buffer_size_tx = TX_BUF_LEN,
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        .crt_bundle_attach = esp_crt_bundle_attach,
#endif
    };
    /* len == 0 means PEM, so derive it; non-zero is used verbatim. */
    if (cfg->client_cert) {
        esp_cfg.client_cert_pem = cfg->client_cert;
        esp_cfg.client_cert_len = cfg->client_cert_len ? cfg->client_cert_len
                                  : strlen(cfg->client_cert) + 1;
    }
    if (cfg->client_key) {
        esp_cfg.client_key_pem = cfg->client_key;
        esp_cfg.client_key_len = cfg->client_key_len ? cfg->client_key_len
                                 : strlen(cfg->client_key) + 1;
    }
    esp_http_client_handle_t client = esp_http_client_init(&esp_cfg);
    if (!client) {
        return ESP_FAIL;
    }
    *out = (esp_rmaker_aws_sign_http_handle_t)client;
    return ESP_OK;
}

static esp_err_t esp_http_set_url(esp_rmaker_aws_sign_http_handle_t h, const char *url)
{
    return esp_http_client_set_url((esp_http_client_handle_t)h, url);
}

static esp_err_t esp_http_set_method(esp_rmaker_aws_sign_http_handle_t h,
                                     esp_rmaker_aws_sign_http_method_t method)
{
    return esp_http_client_set_method((esp_http_client_handle_t)h, to_esp_method(method));
}

static esp_err_t esp_http_set_header(esp_rmaker_aws_sign_http_handle_t h, const char *name,
                                     const char *value)
{
    /* esp_http_client_set_header() overwrites by key, and deletes on a NULL value. */
    return esp_http_client_set_header((esp_http_client_handle_t)h, name, value);
}

static esp_err_t esp_http_perform(esp_rmaker_aws_sign_http_handle_t h, const uint8_t *body,
                                  size_t body_len,
                                  const esp_rmaker_aws_sign_http_receiver_t *rx)
{
    esp_http_client_handle_t client = (esp_http_client_handle_t)h;

    esp_err_t err = esp_http_client_open(client, (int)body_len);
    if (err != ESP_OK) {
        return err;
    }
    if (body_len) {
        int written = esp_http_client_write(client, (const char *)body, (int)body_len);
        if (written < 0 || (size_t)written != body_len) {
            return ESP_FAIL;
        }
    }
    /* 0 means chunked or no Content-Length, which is what hint expects too. */
    int64_t content_length = esp_http_client_fetch_headers(client);
    if (content_length < 0) {
        return ESP_FAIL;
    }
    if (rx->hint && rx->hint(rx->ctx, (size_t)content_length) != 0) {
        return ESP_ERR_INVALID_SIZE;
    }
    char buf[READ_CHUNK_LEN];
    while (1) {
        int len = esp_http_client_read(client, buf, sizeof(buf));
        if (len < 0) {
            return ESP_FAIL;
        }
        if (len == 0) {
            break;
        }
        if (rx->sink && rx->sink(rx->ctx, (const uint8_t *)buf, (size_t)len) < len) {
            return ESP_ERR_INVALID_SIZE;    /* sink consumed less than it was given */
        }
    }
    /* Not closed: staying connected is what lets the next perform() reuse the
     * TLS session. */
    return ESP_OK;
}

static int esp_http_status_code(esp_rmaker_aws_sign_http_handle_t h)
{
    return esp_http_client_get_status_code((esp_http_client_handle_t)h);
}

static void esp_http_close(esp_rmaker_aws_sign_http_handle_t h)
{
    esp_http_client_handle_t client = (esp_http_client_handle_t)h;
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_http_ops_t esp_rmaker_aws_sign_esp_http_ops = {
    .open = esp_http_open,
    .set_url = esp_http_set_url,
    .set_method = esp_http_set_method,
    .set_header = esp_http_set_header,
    .perform = esp_http_perform,
    .status_code = esp_http_status_code,
    .close = esp_http_close,
};
