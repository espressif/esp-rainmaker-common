/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_send_request.c
 * @brief Credentials + signature + HTTPS round trip in one call.
 *
 * @note The pooled connection belongs to the handle, so calls on one handle are serialized.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "esp_rmaker_aws_sign_internal.h"

#define CONTENT_TYPE_NAME    "Content-Type"
#define CONTENT_TYPE_DEFAULT "application/json"

static const char *TAG = "esp_rmaker_aws_sign_request";

void esp_rmaker_aws_sign_request_conn_close(esp_rmaker_aws_sign_handle_t h)
{
    if (h->conn) {
        g_esp_rmaker_aws_sign_port.http.close(h->conn);
        h->conn = NULL;
    }
    h->conn_host[0] = '\0';
    h->conn_last_use = 0;
    h->conn_timeout_ms = 0;
}

/* True once the pooled connection has sat idle long enough that the peer is
 * likely to have closed it; a stepped clock counts as stale, never as fresh. */
static bool conn_idle_expired(esp_rmaker_aws_sign_handle_t h)
{
    if (CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_CONN_IDLE_TIMEOUT_SEC <= 0) {
        return false;
    }
    int64_t now = (int64_t)g_esp_rmaker_aws_sign_port.time.get_time(NULL);
    int64_t idle = now - h->conn_last_use;
    return idle < 0 || idle >= CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_CONN_IDLE_TIMEOUT_SEC;
}

void esp_rmaker_aws_sign_response_free(esp_rmaker_aws_sign_response_t *resp)
{
    if (!resp || !esp_rmaker_aws_sign_port_is_installed()) {
        return;
    }
    AWS_FREE(resp->body);
    memset(resp, 0, sizeof(*resp));
}

static esp_err_t method_to_enum(const char *method, esp_rmaker_aws_sign_http_method_t *out)
{
    if (strcmp(method, "GET") == 0) {
        *out = ESP_RMAKER_AWS_SIGN_HTTP_GET;
    } else if (strcmp(method, "POST") == 0) {
        *out = ESP_RMAKER_AWS_SIGN_HTTP_POST;
    } else if (strcmp(method, "PUT") == 0) {
        *out = ESP_RMAKER_AWS_SIGN_HTTP_PUT;
    } else if (strcmp(method, "DELETE") == 0) {
        *out = ESP_RMAKER_AWS_SIGN_HTTP_DELETE;
    } else if (strcmp(method, "PATCH") == 0) {
        *out = ESP_RMAKER_AWS_SIGN_HTTP_PATCH;
    } else {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

bool esp_rmaker_aws_sign_method_supported(const char *method)
{
    esp_rmaker_aws_sign_http_method_t ignored;
    return method != NULL && method_to_enum(method, &ignored) == ESP_OK;
}

/* The path is encoded once here; the signer encodes it again for a non-S3 canonical URI. */
static char *build_url(const esp_rmaker_aws_sign_request_t *req, const char *query)
{
    bool has_query = query && query[0];
    size_t prefix_len = strlen("https://") + strlen(req->host);
    size_t path_len = esp_rmaker_aws_sign_uri_encode_into(NULL, 0, req->path, true, false);
    size_t len = prefix_len + path_len + (has_query ? 1 + strlen(query) : 0) + 1;
    char *url = AWS_CALLOC(1, len);
    if (url) {
        snprintf(url, len, "https://%s", req->host);
        esp_rmaker_aws_sign_uri_encode_into(url + prefix_len, len - prefix_len, req->path,
                                            true, false);
        if (has_query) {
            snprintf(url + prefix_len + path_len, len - prefix_len - path_len, "?%s", query);
        }
    }
    return url;
}

/* Reuse the pooled handle when the host and timeout match, skipping the TLS handshake;
 * every request overwrites the headers it sets, and clears its own. Reports
 * whether the handle came from the pool, which decides if a failure is retried. */
static esp_err_t conn_get(esp_rmaker_aws_sign_handle_t h,
                          const esp_rmaker_aws_sign_request_t *req, const char *url,
                          esp_rmaker_aws_sign_http_method_t method,
                          esp_rmaker_aws_sign_http_handle_t *out, bool *reused)
{
    const esp_rmaker_aws_sign_http_ops_t *http = &g_esp_rmaker_aws_sign_port.http;
    int timeout_ms = req->timeout_ms ? req->timeout_ms
                     : CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_HTTP_TIMEOUT_MS;

    /* The port sets the timeout only at open, so a different one needs a new handle. */
    if (h->conn && (strcmp(h->conn_host, req->host) != 0 || h->conn_timeout_ms != timeout_ms)) {
        esp_rmaker_aws_sign_request_conn_close(h);
    }
    if (h->conn && conn_idle_expired(h)) {
        AWS_LOGD(TAG, "Pooled connection to %s idle too long; reconnecting", h->conn_host);
        esp_rmaker_aws_sign_request_conn_close(h);
    }
    *reused = false;
    if (h->conn) {
        esp_err_t err = http->set_url(h->conn, url);
        if (err == ESP_OK) {
            err = http->set_method(h->conn, method);
        }
        if (err != ESP_OK) {
            esp_rmaker_aws_sign_request_conn_close(h);
        } else {
            *out = h->conn;
            *reused = true;
            return ESP_OK;
        }
    }
    esp_rmaker_aws_sign_http_config_t cfg = {
        .url = url,
        .method = method,
        .client_cert = h->client_cert,
        .client_cert_len = h->client_cert_len,
        .client_key = h->client_key,
        .client_key_len = h->client_key_len,
        .timeout_ms = timeout_ms,
        .keep_alive = true,
    };
    esp_err_t err = http->open(&cfg, &h->conn);
    if (err != ESP_OK) {
        h->conn = NULL;
        return err;
    }
    snprintf(h->conn_host, sizeof(h->conn_host), "%s", req->host);
    h->conn_timeout_ms = timeout_ms;
    *out = h->conn;
    return ESP_OK;
}

static bool has_content_type(const esp_rmaker_aws_sign_header_t *hdrs, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (hdrs[i].name && strcasecmp(hdrs[i].name, CONTENT_TYPE_NAME) == 0) {
            return true;
        }
    }
    return false;
}

static bool needs_content_type(const esp_rmaker_aws_sign_request_t *req)
{
    return req->payload && req->payload_len
           && !has_content_type(req->extra_headers, req->extra_headers_count);
}

/* The caller's headers with a default Content-Type appended, so the header that
 * goes on the wire is the one that gets signed. NULL on allocation failure. */
static esp_rmaker_aws_sign_header_t *with_content_type(const esp_rmaker_aws_sign_request_t *req,
                                                       size_t *out_count)
{
    size_t count = req->extra_headers_count + 1;
    esp_rmaker_aws_sign_header_t *hdrs = AWS_CALLOC(count, sizeof(esp_rmaker_aws_sign_header_t));
    if (!hdrs) {
        return NULL;
    }
    if (req->extra_headers_count) {
        memcpy(hdrs, req->extra_headers, req->extra_headers_count * sizeof(*hdrs));
    }
    hdrs[count - 1] = (esp_rmaker_aws_sign_header_t) { CONTENT_TYPE_NAME, CONTENT_TYPE_DEFAULT };
    *out_count = count;
    return hdrs;
}

/* Leave the pooled handle holding only the headers every request overwrites. */
static void clear_caller_headers(esp_rmaker_aws_sign_http_handle_t h,
                                 const esp_rmaker_aws_sign_header_t *hdrs, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        g_esp_rmaker_aws_sign_port.http.set_header(h, hdrs[i].name, NULL);
    }
}

static esp_err_t set_request_headers(esp_rmaker_aws_sign_http_handle_t h,
                                     const esp_rmaker_aws_sign_header_t *hdrs, size_t hdrs_count,
                                     const esp_rmaker_aws_sign_sigv4_output_t *sig,
                                     const char *session_token)
{
    const esp_rmaker_aws_sign_http_ops_t *http = &g_esp_rmaker_aws_sign_port.http;
    esp_err_t err = http->set_header(h, "Authorization", sig->authorization_header);
    if (err == ESP_OK) {
        err = http->set_header(h, "x-amz-date", sig->amz_date);
    }
    if (err == ESP_OK) {
        err = http->set_header(h, "x-amz-content-sha256", sig->content_sha256);
    }
    if (err == ESP_OK && session_token) {
        err = http->set_header(h, "x-amz-security-token", session_token);
    }
    for (size_t i = 0; err == ESP_OK && i < hdrs_count; i++) {
        err = http->set_header(h, hdrs[i].name, hdrs[i].value);
    }
    return err;
}

esp_err_t esp_rmaker_aws_sign_send_request(esp_rmaker_aws_sign_handle_t handle,
                                           const esp_rmaker_aws_sign_request_t *req,
                                           esp_rmaker_aws_sign_response_t *resp)
{
    if (!esp_rmaker_aws_sign_handle_valid(handle)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!req || !resp || !req->method || !req->host || !req->path || !req->service
            || !req->role_alias || !req->creds || req->path[0] != '/'
            || (req->extra_headers_count && !req->extra_headers)
            || (req->payload_len && !req->payload)) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_rmaker_aws_sign_http_method_t method;
    esp_err_t err = method_to_enum(req->method, &method);
    if (err != ESP_OK) {
        return err;
    }
    memset(resp, 0, sizeof(*resp));

    const esp_rmaker_aws_sign_http_ops_t *http = &g_esp_rmaker_aws_sign_port.http;
    esp_rmaker_aws_sign_sigv4_output_t sig = {0};
    esp_rmaker_aws_sign_sigv4_input_t in = {0};
    esp_rmaker_aws_sign_http_handle_t h = NULL;
    char *url = NULL;
    char *query = NULL;
    const esp_rmaker_aws_sign_header_t *hdrs = req->extra_headers;
    size_t hdrs_count = req->extra_headers_count;
    esp_rmaker_aws_sign_header_t *hdrs_owned = NULL;
    esp_rmaker_aws_sign_accum_t acc;
    esp_rmaker_aws_sign_accum_init(&acc, CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX);

    /* Built once: the URL and the signature must carry the same encoding. */
    err = esp_rmaker_aws_sign_build_query(req->params, req->params_count, &query);
    if (err != ESP_OK) {
        return err;
    }

    /* Also holds the region steady while this call signs. */
    g_esp_rmaker_aws_sign_port.mutex.lock(handle->request_mutex);

    const esp_rmaker_aws_sign_creds_t *creds = req->creds;
    err = esp_rmaker_aws_sign_creds_refresh(handle, req->role_alias, req->creds);
    if (err != ESP_OK) {
        goto out;
    }
    if (needs_content_type(req)) {
        hdrs_owned = with_content_type(req, &hdrs_count);
        if (!hdrs_owned) {
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        hdrs = hdrs_owned;
    }

    in = (esp_rmaker_aws_sign_sigv4_input_t) {
        .method = req->method,
        .host = req->host,
        .path = req->path,
        .headers = hdrs,
        .headers_count = hdrs_count,
        .payload = req->payload,
        .payload_len = req->payload_len,
        .sign_payload_hash = true,
        .access_key_id = creds->access_key_id,
        .secret_access_key = creds->secret_access_key,
        .session_token = creds->session_token,
        .region = req->region ? req->region : handle->region,
        .service = req->service,
        .now_epoch_sec = (int64_t)g_esp_rmaker_aws_sign_port.time.get_time(NULL),
    };
    err = esp_rmaker_aws_sign_sigv4_with_query(&in, query, &sig);
    if (err != ESP_OK) {
        goto out;
    }

    url = build_url(req, query);
    if (!url) {
        err = ESP_ERR_NO_MEM;
        goto out;
    }

    /* One retry, when a reused handle fails before any response: the peer may have dropped
     * it while idle. Once a response starts, the server has acted, so it is never resent. */
    for (int attempt = 0; ; attempt++) {
        bool reused = false;
        err = conn_get(handle, req, url, method, &h, &reused);
        if (err != ESP_OK) {
            AWS_LOGE(TAG, "Could not connect to %s: 0x%x", req->host, err);
            goto out;
        }
        err = set_request_headers(h, hdrs, hdrs_count, &sig, creds->session_token);
        if (err != ESP_OK) {
            goto out;
        }
        esp_rmaker_aws_sign_http_receiver_t rx = esp_rmaker_aws_sign_accum_receiver(&acc);
        err = http->perform(h, req->payload, req->payload_len, &rx);
        if (acc.status != ESP_OK) {
            err = acc.status;               /* also covers a port that ignored the abort */
        }
        if (err == ESP_OK) {
            handle->conn_last_use = (int64_t)g_esp_rmaker_aws_sign_port.time.get_time(NULL);
            break;
        }
        /* An aborted or failed transfer leaves the connection unusable. */
        esp_rmaker_aws_sign_request_conn_close(handle);
        h = NULL;
        if (attempt == 0 && reused && acc.status == ESP_OK && !acc.got_response) {
            AWS_LOGW(TAG, "Request to %s failed on the pooled connection (0x%x); retrying",
                     req->host, err);
            esp_rmaker_aws_sign_accum_reset(&acc);
            continue;
        }
        if (acc.status == ESP_ERR_INVALID_SIZE) {
            AWS_LOGE(TAG, "Response exceeds %d bytes", (int)acc.limit);
        } else {
            AWS_LOGE(TAG, "Request to %s failed: 0x%x", req->host, err);
        }
        goto out;
    }
    resp->status_code = http->status_code(h);
    /* Ownership moves to the caller: exact when the reply declared its length. */
    resp->body = acc.buf;
    resp->body_len = acc.len;
    acc.buf = NULL;

out:
    if (h && h == handle->conn) {
        clear_caller_headers(h, hdrs, hdrs_count);
    }
    g_esp_rmaker_aws_sign_port.mutex.unlock(handle->request_mutex);
    esp_rmaker_aws_sign_sigv4_output_free(&sig);
    AWS_FREE(hdrs_owned);
    AWS_FREE(url);
    AWS_FREE(query);
    esp_rmaker_aws_sign_accum_free(&acc);
    return err;
}
