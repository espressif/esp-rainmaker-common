/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_internal.h
 * @brief The installed port, the handle layout and the pure helpers tests drive.
 *
 * @note Nothing here may name a backend: all of it enters via the port.
 */

#pragma once

#include "esp_rmaker_aws_sign.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Kconfig fallbacks, so the platform-independent half builds without one. */
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_MIN_VALID_EPOCH
#define CONFIG_ESP_RMAKER_AWS_SIGN_MIN_VALID_EPOCH 1735689600
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_HTTP_TIMEOUT_MS
#define CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_HTTP_TIMEOUT_MS 10000
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX
#define CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX 4096
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC
#define CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC 300
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_DEFAULT_TTL_SEC
#define CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_DEFAULT_TTL_SEC 3000
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_HTTP_TIMEOUT_MS
#define CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_HTTP_TIMEOUT_MS 15000
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_CONN_IDLE_TIMEOUT_SEC
#define CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_CONN_IDLE_TIMEOUT_SEC 10
#endif
#ifndef CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX
#define CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX 8192
#endif

/* The installed port ---------------------------------------------------------*/

extern esp_rmaker_aws_sign_port_config_t g_esp_rmaker_aws_sign_port;

/** @brief Remove the installed port; tests only, with no handle alive. */
void esp_rmaker_aws_sign_port_uninstall(void);

void esp_rmaker_aws_sign_log(esp_rmaker_aws_sign_log_level_t level, const char *tag,
                             const char *format, ...) __attribute__((format(printf, 3, 4)));

#define AWS_MALLOC(n)     g_esp_rmaker_aws_sign_port.mem.malloc(n)
#define AWS_CALLOC(n, s)  g_esp_rmaker_aws_sign_port.mem.calloc((n), (s))
static inline void aws_free(void *p)
{
    if (p) {
        g_esp_rmaker_aws_sign_port.mem.free(p);
    }
}
#define AWS_FREE(p)       aws_free(p)
#define AWS_CRYPTO        (&g_esp_rmaker_aws_sign_port.crypto)

/* Best-effort secure erase: the volatile access stops most compilers eliding
 * the stores, and the core links no crypto library to borrow one from. */
static inline void aws_zeroize(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

#define AWS_LOGE(tag, fmt, ...) \
    esp_rmaker_aws_sign_log(ESP_RMAKER_AWS_SIGN_LOG_ERROR, tag, fmt, ##__VA_ARGS__)
#define AWS_LOGW(tag, fmt, ...) \
    esp_rmaker_aws_sign_log(ESP_RMAKER_AWS_SIGN_LOG_WARN, tag, fmt, ##__VA_ARGS__)
#define AWS_LOGI(tag, fmt, ...) \
    esp_rmaker_aws_sign_log(ESP_RMAKER_AWS_SIGN_LOG_INFO, tag, fmt, ##__VA_ARGS__)
#define AWS_LOGD(tag, fmt, ...) \
    esp_rmaker_aws_sign_log(ESP_RMAKER_AWS_SIGN_LOG_DEBUG, tag, fmt, ##__VA_ARGS__)

/* Handle ---------------------------------------------------------------------*/

#define ESP_RMAKER_AWS_SIGN_REGION_LEN    32
#define ESP_RMAKER_AWS_SIGN_CONN_HOST_LEN 160
#define ESP_RMAKER_AWS_SIGN_CTX_MAGIC     0x41575353u   /* "AWSS" */

/** Config copy, the three locks and the pooled connection. Lock order:
 *  request_mutex, then creds_mutex, then region_mutex. */
struct esp_rmaker_aws_sign_ctx {
    uint32_t magic;                     /**< ESP_RMAKER_AWS_SIGN_CTX_MAGIC while the handle is live */
    char    *cred_host;                 /**< guarded by creds_mutex */
    uint32_t cred_host_gen;             /**< guarded by creds_mutex; never 0 */
    char     region[ESP_RMAKER_AWS_SIGN_REGION_LEN];   /**< write: all locks; read: request or region */
    char    *thing_name;
    char    *client_cert;
    size_t   client_cert_len;
    char    *client_key;
    size_t   client_key_len;
    esp_rmaker_aws_sign_mutex_t creds_mutex;
    esp_rmaker_aws_sign_mutex_t request_mutex;
    esp_rmaker_aws_sign_mutex_t region_mutex;   /**< never held across I/O */
    esp_rmaker_aws_sign_http_handle_t conn;     /**< pooled; the conn fields are guarded by request_mutex */
    char     conn_host[ESP_RMAKER_AWS_SIGN_CONN_HOST_LEN];
    int64_t  conn_last_use;
    int      conn_timeout_ms;
};

/** @brief True for a live handle; logs and returns false for any other value. */
bool esp_rmaker_aws_sign_handle_valid(esp_rmaker_aws_sign_handle_t h);

/** @brief True when the wall clock may be trusted for x-amz-date. */
bool esp_rmaker_aws_sign_clock_is_trustworthy(void);

/** @brief Drop the pooled signed-request connection of @c h. */
void esp_rmaker_aws_sign_request_conn_close(esp_rmaker_aws_sign_handle_t h);

/* Response accumulator ------------------------------------------------------*/

/** Grows on demand up to @c limit, so a small response costs a small buffer. */
typedef struct {
    uint8_t  *buf;      /**< NUL-terminated at @c len; NULL until the first hint or write */
    size_t    len;
    size_t    cap;
    size_t    limit;    /**< largest body accepted, excluding the terminator */
    esp_err_t status;   /**< why the sink aborted: NO_MEM or INVALID_SIZE */
    bool      got_response;   /**< the hint or a body chunk arrived */
} esp_rmaker_aws_sign_accum_t;

void esp_rmaker_aws_sign_accum_init(esp_rmaker_aws_sign_accum_t *a, size_t limit);

/** @brief The receiver that fills @c a: the only way to obtain its callbacks. */
esp_rmaker_aws_sign_http_receiver_t
esp_rmaker_aws_sign_accum_receiver(esp_rmaker_aws_sign_accum_t *a);

/** @brief Empty @c a for reuse, keeping its buffer. */
void esp_rmaker_aws_sign_accum_reset(esp_rmaker_aws_sign_accum_t *a);

void esp_rmaker_aws_sign_accum_free(esp_rmaker_aws_sign_accum_t *a);

/* Pure helpers, exposed for tests -------------------------------------------*/

char *esp_rmaker_aws_sign_strdup(const char *s);

/**
 * @brief URI-encode @c src into @c dst per RFC 3986, uppercase %XX.
 *
 * @param[in] keep_slash Pass '/' through literally, as a path does.
 * @param[in] twice      Encode the output again, as every non-S3 path requires.
 *
 * @return Bytes the encoding needs excluding the NUL; more than @c cap - 1 means
 *         @c dst holds a truncated string.
 */
size_t esp_rmaker_aws_sign_uri_encode_into(char *dst, size_t cap, const char *src,
                                           bool keep_slash, bool twice);

/**
 * @brief Normalize the path @c src as SigV4 does for a non-S3 canonical URI, without encoding.
 *
 * @return Bytes the result needs excluding the NUL; more than @c cap - 1 means
 *         @c dst holds a truncated string.
 */
size_t esp_rmaker_aws_sign_normalize_path_into(char *dst, size_t cap, const char *src);

/**
 * @brief Copy @c src trimmed, with internal whitespace runs collapsed to one space.
 *
 * @return Bytes the trimmed value needs excluding the NUL.
 */
size_t esp_rmaker_aws_sign_trim_header_value(char *dst, size_t cap, const char *src);

/**
 * @brief Build the ';'-joined lowercased SignedHeaders string.
 *
 * @note @c sorted must already be stable-sorted; release @c *out with AWS_FREE().
 */
esp_err_t esp_rmaker_aws_sign_build_signed_headers(const esp_rmaker_aws_sign_header_t *sorted,
                                                   int n, char **out);

/**
 * @brief Encode each parameter, then sort by encoded name and value: a canonical query.
 *
 * @note Zero parameters give a NULL @c *out; release it with AWS_FREE().
 */
esp_err_t esp_rmaker_aws_sign_build_query(const esp_rmaker_aws_sign_query_param_t *params,
                                          size_t count, char **out);

/** @brief Sign with a canonical query already built; @c in->params is ignored. */
esp_err_t esp_rmaker_aws_sign_sigv4_with_query(const esp_rmaker_aws_sign_sigv4_input_t *in,
                                               const char *query,
                                               esp_rmaker_aws_sign_sigv4_output_t *out);

/** @brief "2026-06-11T08:31:00Z" -> epoch seconds; 0 when absent or malformed. */
int64_t esp_rmaker_aws_sign_iso8601_to_epoch(const char *iso);

/**
 * @brief Parse a credential-provider response body. Pure: no clock, no IO.
 *
 * @note @c expiration_epoch_sec is the raw parse result, 0 when absent or
 *       malformed, so the caller applies the fallback-TTL policy.
 */
esp_err_t esp_rmaker_aws_sign_parse_creds_json(const char *json, size_t len,
                                               esp_rmaker_aws_sign_creds_t *out);

#ifdef __cplusplus
}
#endif
