/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_creds.c
 * @brief Handle lifecycle and the IoT Credential Provider client.
 *
 * @note Names no HTTP client, clock or parser: all of it enters via the port.
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_rmaker_aws_sign_internal.h"

#define AK_BUF_LEN   128
#define SK_BUF_LEN   128
#define EXP_BUF_LEN  32
#define TOK_BUF_LEN  CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX

static const char *TAG = "esp_rmaker_aws_sign_creds";

/* Shared by every handle, so a struct filled by one handle never matches another. */
static atomic_uint s_last_host_gen;

static void state_lock(esp_rmaker_aws_sign_mutex_t m)
{
    g_esp_rmaker_aws_sign_port.mutex.lock(m);
}

static void state_unlock(esp_rmaker_aws_sign_mutex_t m)
{
    g_esp_rmaker_aws_sign_port.mutex.unlock(m);
}

bool esp_rmaker_aws_sign_handle_valid(esp_rmaker_aws_sign_handle_t h)
{
    if (h && h->magic == ESP_RMAKER_AWS_SIGN_CTX_MAGIC) {
        return true;
    }
    AWS_LOGE(TAG, "Invalid handle %p; use one from esp_rmaker_aws_sign_create()", (void *)h);
    return false;
}

/* Lifecycle ******************************************************************/

/* PEM when len == 0, so strlen()+1; otherwise an explicitly sized DER blob. */
static char *copy_blob(const char *src, size_t len, size_t *out_len)
{
    if (src == NULL) {
        *out_len = 0;
        return NULL;
    }
    size_t n = len ? len : strlen(src) + 1;
    char *copy = AWS_CALLOC(1, n);
    if (copy) {
        memcpy(copy, src, n);
        *out_len = len;
    }
    return copy;
}

static uint32_t next_host_gen(void)
{
    uint32_t gen;
    do {
        gen = (uint32_t)atomic_fetch_add(&s_last_host_gen, 1) + 1;
    } while (gen == 0);                 /* 0 marks a struct that was never fetched */
    return gen;
}

/* @c region when given, else parsed from @c host; copied into @c out. */
static esp_err_t region_resolve(const char *host, const char *region,
                                char out[ESP_RMAKER_AWS_SIGN_REGION_LEN])
{
    char *parsed = region ? NULL : esp_rmaker_aws_sign_parse_region_from_host(host);
    const char *src = region ? region : parsed;
    esp_err_t err = ESP_OK;
    if (!src) {
        AWS_LOGE(TAG, "No region given and none parseable from the credential host");
        err = ESP_ERR_INVALID_ARG;
    } else if (snprintf(out, ESP_RMAKER_AWS_SIGN_REGION_LEN, "%s", src)
               >= ESP_RMAKER_AWS_SIGN_REGION_LEN) {
        AWS_LOGE(TAG, "Region \"%s\" is too long", src);
        err = ESP_ERR_INVALID_ARG;
    }
    AWS_FREE(parsed);
    return err;
}

/* Takes a partly built handle too, so create can unwind through it. */
static void ctx_free(esp_rmaker_aws_sign_handle_t h)
{
    h->magic = 0;
    AWS_FREE(h->cred_host);
    AWS_FREE(h->thing_name);
    AWS_FREE(h->client_cert);
    if (h->client_key) {
        aws_zeroize(h->client_key, h->client_key_len ? h->client_key_len : strlen(h->client_key) + 1);
    }
    AWS_FREE(h->client_key);
    if (h->creds_mutex) {
        g_esp_rmaker_aws_sign_port.mutex.destroy(h->creds_mutex);
    }
    if (h->request_mutex) {
        g_esp_rmaker_aws_sign_port.mutex.destroy(h->request_mutex);
    }
    if (h->region_mutex) {
        g_esp_rmaker_aws_sign_port.mutex.destroy(h->region_mutex);
    }
    AWS_FREE(h);
}

esp_err_t esp_rmaker_aws_sign_create(const esp_rmaker_aws_sign_config_t *config,
                                     esp_rmaker_aws_sign_handle_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    *out = NULL;
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        /* No port means no log sink, so the return code is the only report. */
        return ESP_ERR_INVALID_STATE;
    }
    if (g_esp_rmaker_aws_sign_port.http.open == NULL) {
        AWS_LOGE(TAG, "The installed port has no http ops; only the signer is available");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!config || !config->cred_host || !config->thing_name || !config->client_cert
            || !config->client_key) {
        AWS_LOGE(TAG, "Config needs cred_host, thing_name, client_cert and client_key");
        return ESP_ERR_INVALID_ARG;
    }
    esp_rmaker_aws_sign_handle_t h = AWS_CALLOC(1, sizeof(struct esp_rmaker_aws_sign_ctx));
    if (!h) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = region_resolve(config->cred_host, config->region, h->region);
    if (err != ESP_OK) {
        ctx_free(h);
        return err;
    }
    h->cred_host = esp_rmaker_aws_sign_strdup(config->cred_host);
    h->cred_host_gen = next_host_gen();
    h->thing_name = esp_rmaker_aws_sign_strdup(config->thing_name);
    h->client_cert = copy_blob(config->client_cert, config->client_cert_len, &h->client_cert_len);
    h->client_key = copy_blob(config->client_key, config->client_key_len, &h->client_key_len);
    h->creds_mutex = g_esp_rmaker_aws_sign_port.mutex.create();
    h->request_mutex = g_esp_rmaker_aws_sign_port.mutex.create();
    h->region_mutex = g_esp_rmaker_aws_sign_port.mutex.create();
    if (!h->cred_host || !h->thing_name || !h->client_cert || !h->client_key
            || !h->creds_mutex || !h->request_mutex || !h->region_mutex) {
        ctx_free(h);
        return ESP_ERR_NO_MEM;
    }
    h->magic = ESP_RMAKER_AWS_SIGN_CTX_MAGIC;
    *out = h;
    return ESP_OK;
}

void esp_rmaker_aws_sign_destroy(esp_rmaker_aws_sign_handle_t handle)
{
    if (!handle || !esp_rmaker_aws_sign_handle_valid(handle)) {
        return;
    }
    esp_rmaker_aws_sign_request_conn_close(handle);
    ctx_free(handle);
}

esp_err_t esp_rmaker_aws_sign_set_cred_host(esp_rmaker_aws_sign_handle_t handle,
                                            const char *cred_host, const char *region)
{
    if (!esp_rmaker_aws_sign_handle_valid(handle) || !cred_host) {
        return ESP_ERR_INVALID_ARG;
    }
    char new_region[ESP_RMAKER_AWS_SIGN_REGION_LEN];
    esp_err_t err = region_resolve(cred_host, region, new_region);
    if (err != ESP_OK) {
        return err;
    }
    char *host = esp_rmaker_aws_sign_strdup(cred_host);
    if (!host) {
        return ESP_ERR_NO_MEM;
    }
    state_lock(handle->request_mutex);
    state_lock(handle->creds_mutex);
    AWS_FREE(handle->cred_host);
    handle->cred_host = host;
    handle->cred_host_gen = next_host_gen();
    state_lock(handle->region_mutex);
    memcpy(handle->region, new_region, sizeof(handle->region));
    state_unlock(handle->region_mutex);
    state_unlock(handle->creds_mutex);
    state_unlock(handle->request_mutex);
    return ESP_OK;
}

esp_err_t esp_rmaker_aws_sign_get_region(esp_rmaker_aws_sign_handle_t handle,
                                         char *buf, size_t buf_len)
{
    if (!esp_rmaker_aws_sign_handle_valid(handle) || !buf || !buf_len) {
        return ESP_ERR_INVALID_ARG;
    }
    state_lock(handle->region_mutex);
    size_t len = strlen(handle->region);
    esp_err_t err = ESP_ERR_INVALID_SIZE;
    if (len < buf_len) {
        memcpy(buf, handle->region, len + 1);
        err = ESP_OK;
    }
    state_unlock(handle->region_mutex);
    return err;
}

/* Pure helpers ***************************************************************/

char *esp_rmaker_aws_sign_parse_region_from_host(const char *host)
{
    if (!host || !esp_rmaker_aws_sign_port_is_installed()) {
        return NULL;
    }
    /* The label before the first ".amazonaws.", which is what makes the
     * amazonaws.com.cn partition work too. */
    const char *aws = strstr(host, ".amazonaws.");
    if (!aws) {
        return NULL;
    }
    const char *start = aws;
    while (start > host && *(start - 1) != '.') {
        start--;
    }
    size_t len = (size_t)(aws - start);
    if (len == 0) {
        return NULL;
    }
    char *region = AWS_CALLOC(1, len + 1);
    if (region) {
        memcpy(region, start, len);
    }
    return region;
}

/* Days since 1970-01-01, computed here rather than with timegm(), which is
 * absent on some libcs and TZ-sensitive on others. */
static int64_t days_from_civil(int y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

int64_t esp_rmaker_aws_sign_iso8601_to_epoch(const char *iso)
{
    if (!iso) {
        return 0;
    }
    int y, mo, d, h, mi, s;
    if (sscanf(iso, "%d-%d-%dT%d:%d:%dZ", &y, &mo, &d, &h, &mi, &s) != 6) {
        return 0;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60
            || h < 0 || mi < 0 || s < 0) {
        return 0;
    }
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

/* The three strings share one block that starts at access_key_id. */
void esp_rmaker_aws_sign_creds_free(esp_rmaker_aws_sign_creds_t *creds)
{
    if (!creds || !esp_rmaker_aws_sign_port_is_installed()) {
        return;
    }
    char *fields[] = { creds->access_key_id, creds->secret_access_key, creds->session_token };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (fields[i]) {
            aws_zeroize(fields[i], strlen(fields[i]) + 1);
        }
    }
    AWS_FREE(creds->access_key_id);
    memset(creds, 0, sizeof(*creds));
}

esp_err_t esp_rmaker_aws_sign_parse_creds_json(const char *json, size_t len,
                                               esp_rmaker_aws_sign_creds_t *out)
{
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!json || !len || !out) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!g_esp_rmaker_aws_sign_port.json.read_strs) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    memset(out, 0, sizeof(*out));

    /* The session token runs 0.7-1.5 KB, so it is kept off the stack. */
    size_t tok_size = len < TOK_BUF_LEN ? len + 1 : TOK_BUF_LEN;
    char *tok = AWS_CALLOC(1, tok_size);
    if (!tok) {
        return ESP_ERR_NO_MEM;
    }
    char ak[AK_BUF_LEN], sk[SK_BUF_LEN], expiration[EXP_BUF_LEN];
    enum { AK_F, SK_F, TOK_F, EXP_F, FIELD_COUNT };
    esp_rmaker_aws_sign_json_field_t f[FIELD_COUNT] = {
        [AK_F]  = { .key = "accessKeyId",     .buf = ak,  .buf_size = sizeof(ak) },
        [SK_F]  = { .key = "secretAccessKey", .buf = sk,  .buf_size = sizeof(sk) },
        [TOK_F] = { .key = "sessionToken",    .buf = tok, .buf_size = tok_size },
        [EXP_F] = { .key = "expiration",      .buf = expiration, .buf_size = sizeof(expiration) },
    };

    esp_err_t err = ESP_FAIL;
    if (g_esp_rmaker_aws_sign_port.json.read_strs(json, len, "credentials", f, FIELD_COUNT)
            != ESP_OK) {
        AWS_LOGE(TAG, "Credential response did not parse");
        goto out_free;
    }
    /* expiration is not mandatory; the caller falls back to a default TTL. */
    if (!f[AK_F].found || !f[SK_F].found || !f[TOK_F].found) {
        AWS_LOGE(TAG, "Credential response is missing a mandatory field");
        goto out_free;
    }
    size_t ak_n = strlen(ak) + 1, sk_n = strlen(sk) + 1, tok_n = strlen(tok) + 1;
    char *block = AWS_MALLOC(ak_n + sk_n + tok_n);
    if (!block) {
        err = ESP_ERR_NO_MEM;
        goto out_free;
    }
    out->access_key_id = memcpy(block, ak, ak_n);
    out->secret_access_key = memcpy(block + ak_n, sk, sk_n);
    out->session_token = memcpy(block + ak_n + sk_n, tok, tok_n);
    out->expiration_epoch_sec = f[EXP_F].found
                                ? esp_rmaker_aws_sign_iso8601_to_epoch(expiration) : 0;
    err = ESP_OK;

out_free:
    aws_zeroize(ak, sizeof(ak));
    aws_zeroize(sk, sizeof(sk));
    aws_zeroize(tok, tok_size);
    AWS_FREE(tok);
    return err;
}

/* Clock gate *****************************************************************/

bool esp_rmaker_aws_sign_clock_is_trustworthy(void)
{
    if (g_esp_rmaker_aws_sign_port.time.is_synced) {
        return g_esp_rmaker_aws_sign_port.time.is_synced();
    }
    /* No platform answer, so a plausibility threshold: a NULL member must
     * never mean "assume synced". */
    return (int64_t)g_esp_rmaker_aws_sign_port.time.get_time(NULL)
           > CONFIG_ESP_RMAKER_AWS_SIGN_MIN_VALID_EPOCH;
}

/* Fetch **********************************************************************/

static esp_err_t creds_fetch(esp_rmaker_aws_sign_handle_t h, const char *role_alias,
                             esp_rmaker_aws_sign_creds_t *out)
{
    const esp_rmaker_aws_sign_http_ops_t *http = &g_esp_rmaker_aws_sign_port.http;
    esp_err_t err = ESP_FAIL;

    int url_len = snprintf(NULL, 0, "https://%s/role-aliases/%s/credentials",
                           h->cred_host, role_alias) + 1;
    char *url = AWS_CALLOC(1, (size_t)url_len);
    esp_rmaker_aws_sign_accum_t acc;
    esp_rmaker_aws_sign_accum_init(&acc, CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX);
    if (!url) {
        err = ESP_ERR_NO_MEM;
        goto out_free;
    }
    snprintf(url, (size_t)url_len, "https://%s/role-aliases/%s/credentials",
             h->cred_host, role_alias);

    esp_rmaker_aws_sign_http_config_t cfg = {
        .url = url,
        .method = ESP_RMAKER_AWS_SIGN_HTTP_GET,
        .client_cert = h->client_cert,
        .client_cert_len = h->client_cert_len,
        .client_key = h->client_key,
        .client_key_len = h->client_key_len,
        .timeout_ms = CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_HTTP_TIMEOUT_MS,
        .keep_alive = false,
    };
    esp_rmaker_aws_sign_http_handle_t conn = NULL;
    err = http->open(&cfg, &conn);
    if (err != ESP_OK) {
        AWS_LOGE(TAG, "Could not open the credential connection: 0x%x", err);
        goto out_free;
    }
    /* The server CA is not named here: the port supplies it. */
    if (http->set_header(conn, "x-amzn-iot-thingname", h->thing_name) != ESP_OK
            || http->set_header(conn, "Accept", "application/json") != ESP_OK) {
        err = ESP_FAIL;
        goto out_close;
    }
    esp_rmaker_aws_sign_http_receiver_t rx = esp_rmaker_aws_sign_accum_receiver(&acc);
    err = http->perform(conn, NULL, 0, &rx);
    int status = http->status_code(conn);
    if (acc.status != ESP_OK) {
        err = acc.status;               /* also covers a port that ignored the abort */
    }
    if (err != ESP_OK) {
        AWS_LOGE(TAG, "Credential request failed: 0x%x", err);
        goto out_close;
    }
    if (status / 100 != 2) {
        AWS_LOGE(TAG, "Credential provider returned HTTP %d", status);
        err = ESP_FAIL;
        goto out_close;
    }
    if (acc.len == 0) {
        AWS_LOGE(TAG, "Credential response is empty");
        err = ESP_FAIL;
        goto out_close;
    }
    err = esp_rmaker_aws_sign_parse_creds_json((const char *)acc.buf, acc.len, out);

out_close:
    http->close(conn);
out_free:
    AWS_FREE(url);
    esp_rmaker_aws_sign_accum_free(&acc);
    return err;
}

/* FNV-1a, so a struct records its role alias without a heap copy. Two aliases collide at
 * ~2.3e-10 (three at ~7e-10); a collision only hides a caller passing another alias's struct. */
static uint32_t alias_hash(const char *alias)
{
    uint32_t h = 2166136261u;
    while (*alias) {
        h = (h ^ (uint8_t)*alias++) * 16777619u;
    }
    return h;
}

esp_err_t esp_rmaker_aws_sign_creds_refresh(esp_rmaker_aws_sign_handle_t handle,
                                            const char *role_alias,
                                            esp_rmaker_aws_sign_creds_t *creds)
{
    if (!esp_rmaker_aws_sign_handle_valid(handle) || !role_alias || !creds) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t alias = alias_hash(role_alias);
    if (creds->access_key_id && creds->alias_hash != alias) {
        AWS_LOGE(TAG, "Credentials struct holds another role alias");
        return ESP_ERR_INVALID_ARG;
    }
    /* Every network path routes through here, so the clock check lives here. */
    if (!esp_rmaker_aws_sign_clock_is_trustworthy()) {
        AWS_LOGE(TAG, "Wall clock is not synchronised; refusing to sign");
        return ESP_ERR_INVALID_STATE;
    }

    state_lock(handle->creds_mutex);

    int64_t now = (int64_t)g_esp_rmaker_aws_sign_port.time.get_time(NULL);
    bool stale = !creds->access_key_id
                 || creds->host_gen != handle->cred_host_gen
                 || now >= creds->refresh_epoch_sec;

    esp_err_t err = ESP_OK;
    if (stale) {
        esp_rmaker_aws_sign_creds_t fresh = {0};
        err = creds_fetch(handle, role_alias, &fresh);
        if (err == ESP_OK) {
            /* Each fetch is a full mTLS handshake, so a stale or
             * unparsable expiry gets the fallback window. */
            if (fresh.expiration_epoch_sec <= now) {
                fresh.expiration_epoch_sec = now + CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_DEFAULT_TTL_SEC;
            }
            /* Halfway to expiry when under two margins are left, so short ones are reused. */
            int64_t margin = (fresh.expiration_epoch_sec - now) / 2;
            if (margin > CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC) {
                margin = CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC;
            }
            fresh.refresh_epoch_sec = fresh.expiration_epoch_sec - margin;
            fresh.host_gen = handle->cred_host_gen;
            fresh.alias_hash = alias;
            esp_rmaker_aws_sign_creds_free(creds);
            *creds = fresh;
        }
    }

    state_unlock(handle->creds_mutex);
    return err;
}
