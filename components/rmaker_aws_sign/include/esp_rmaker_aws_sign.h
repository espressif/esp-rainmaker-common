/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign.h
 * @brief AWS SigV4 request signing with the device X.509 certificate as identity.
 *
 * @note Every platform dependency enters through the ops tables below, so this
 *       header pulls in no transitive dependency.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory *********************************************************************/

/** Heap operations. All members are required. */
typedef struct {
    void *(*malloc)(size_t size);
    void *(*calloc)(size_t num, size_t size);
    void (*free)(void *ptr);      /**< never called with NULL */
} esp_rmaker_aws_sign_mem_ops_t;

/* Time ***********************************************************************/

/** Wall-clock operations. @c get_time is required. */
typedef struct {
    /** Current UTC time. Also stored to @c p_time when that is non-NULL. */
    time_t (*get_time)(time_t *p_time);

    /** True when the wall clock may be trusted for x-amz-date. NULL falls back
     *  to a plausibility threshold on get_time(). */
    bool (*is_synced)(void);
} esp_rmaker_aws_sign_time_ops_t;

/* Mutex **********************************************************************/

typedef void *esp_rmaker_aws_sign_mutex_t;

/** Mutual exclusion. All members required when @c http is supplied; unused otherwise. */
typedef struct {
    esp_rmaker_aws_sign_mutex_t (*create)(void);
    void (*lock)(esp_rmaker_aws_sign_mutex_t m);      /**< Blocks indefinitely. */
    void (*unlock)(esp_rmaker_aws_sign_mutex_t m);
    void (*destroy)(esp_rmaker_aws_sign_mutex_t m);
} esp_rmaker_aws_sign_mutex_ops_t;

/* HTTP ***********************************************************************/

typedef void *esp_rmaker_aws_sign_http_handle_t;

typedef enum {
    ESP_RMAKER_AWS_SIGN_HTTP_GET,
    ESP_RMAKER_AWS_SIGN_HTTP_POST,
    ESP_RMAKER_AWS_SIGN_HTTP_PUT,
    ESP_RMAKER_AWS_SIGN_HTTP_DELETE,
    ESP_RMAKER_AWS_SIGN_HTTP_PATCH,
} esp_rmaker_aws_sign_http_method_t;

/** Connection parameters. No server CA: it is platform policy, so the port
 *  chooses one and the core never names it. */
typedef struct {
    const char *url;
    esp_rmaker_aws_sign_http_method_t method;
    const char *client_cert;       /**< mTLS client cert: DER, or NUL-terminated PEM. NULL for none. */
    size_t      client_cert_len;   /**< 0 => PEM, port derives strlen()+1. */
    const char *client_key;
    size_t      client_key_len;
    int         timeout_ms;
    bool        keep_alive;
} esp_rmaker_aws_sign_http_config_t;

/** Response-body sink. Returns bytes consumed; less than @c len aborts the
 *  transfer. @c ctx is the receiver's own pointer. */
typedef int (*esp_rmaker_aws_sign_http_sink_t)(void *ctx, const uint8_t *data, size_t len);

/** Declared response-body size, so the sink can size itself in one allocation.
 *  Returns non-zero to abort the transfer.
 *
 *  @note Called once, after the response headers and before any sink call, with
 *        0 when the response is chunked or declares no length. */
typedef int (*esp_rmaker_aws_sign_http_hint_t)(void *ctx, size_t content_length);

/** Where a response body is delivered: the two callbacks and the context they
 *  are built for, so a caller cannot pair them wrongly.
 *
 *  @note A port passes @c ctx back untouched and never interprets it. */
typedef struct {
    esp_rmaker_aws_sign_http_hint_t hint;   /**< may be NULL */
    esp_rmaker_aws_sign_http_sink_t sink;
    void *ctx;
} esp_rmaker_aws_sign_http_receiver_t;

/** HTTP operations. All-or-nothing: with none, the credentials and
 *  signed-request layers return ESP_ERR_NOT_SUPPORTED and the signer still works. */
typedef struct {
    esp_err_t (*open)(const esp_rmaker_aws_sign_http_config_t *cfg,
                      esp_rmaker_aws_sign_http_handle_t *out);

    /** Retarget an open handle, for keep-alive reuse against the same host. */
    esp_err_t (*set_url)(esp_rmaker_aws_sign_http_handle_t h, const char *url);
    esp_err_t (*set_method)(esp_rmaker_aws_sign_http_handle_t h,
                            esp_rmaker_aws_sign_http_method_t method);

    /** Set one request header, overwriting any previous value for the same name;
     *  a NULL @c value removes the header. */
    esp_err_t (*set_header)(esp_rmaker_aws_sign_http_handle_t h, const char *name, const char *value);

    /** Send the request (writing @c body when @c body_len is non-zero), report the
     *  declared body size to @c rx->hint, then stream the response body to
     *  @c rx->sink. Blocking. */
    esp_err_t (*perform)(esp_rmaker_aws_sign_http_handle_t h, const uint8_t *body, size_t body_len,
                         const esp_rmaker_aws_sign_http_receiver_t *rx);

    int (*status_code)(esp_rmaker_aws_sign_http_handle_t h);
    void (*close)(esp_rmaker_aws_sign_http_handle_t h);
} esp_rmaker_aws_sign_http_ops_t;

/* Crypto *********************************************************************/

/** Opaque streaming SHA-256 context, caller-owned so the hot path allocates
 *  nothing. A port MUST static-assert that its own context fits. */
#define ESP_RMAKER_AWS_SIGN_SHA256_CTX_SIZE 256

typedef struct {
    _Alignas(8) uint8_t opaque[ESP_RMAKER_AWS_SIGN_SHA256_CTX_SIZE];
} esp_rmaker_aws_sign_sha256_ctx_t;

/** Streaming SHA-256 and HMAC-SHA-256. The five digest members are required; @c init is optional.
 *
 *  @note Ports specified algorithms, so a backend must pass the known-answer
 *        vectors in test_app before it is trusted.
 */
typedef struct {
    /** One-time backend setup; port install runs it before any other member. */
    esp_err_t (*init)(void);

    /** Begin a streaming digest in caller-provided storage. */
    esp_err_t (*sha256_init)(esp_rmaker_aws_sign_sha256_ctx_t *ctx);

    /** Absorb @c len bytes. Must accept @c len == 0 as a no-op. */
    esp_err_t (*sha256_update)(esp_rmaker_aws_sign_sha256_ctx_t *ctx, const uint8_t *data, size_t len);

    /** Produce the 32-byte digest and release any internal resources.
     *  @c ctx is invalid afterwards. */
    esp_err_t (*sha256_finish)(esp_rmaker_aws_sign_sha256_ctx_t *ctx, uint8_t out[32]);

    /** Release an unfinished context. Must tolerate a context that was never
     *  successfully initialised, so error paths can call it unconditionally. */
    void (*sha256_abort)(esp_rmaker_aws_sign_sha256_ctx_t *ctx);

    /** HMAC-SHA-256, RFC 2104. Must accept a key of ANY length. A port member
     *  rather than a core derivation so a backend can reach a MAC accelerator. */
    esp_err_t (*hmac_sha256)(const uint8_t *key, size_t key_len,
                             const uint8_t *msg, size_t msg_len, uint8_t out[32]);
} esp_rmaker_aws_sign_crypto_ops_t;

/* JSON ***********************************************************************/

/** One field to read. @c key, @c buf and @c buf_size are inputs; @c len and
 *  @c found are outputs. */
typedef struct {
    const char *key;       /**< in:  key to look up within the target object. */
    char       *buf;       /**< in:  destination for the NUL-terminated, unescaped value. */
    size_t      buf_size;  /**< in:  capacity of @c buf, including the NUL. */
    size_t      len;       /**< out: bytes written, excluding the NUL. */
    bool        found;     /**< out: false if the key was absent from the document. */
} esp_rmaker_aws_sign_json_field_t;

/** Field extraction from a JSON document. The single member is required.
 *
 *  @note Not a JSON parser interface: the narrow surface is what makes the
 *        contract pinnable across backends. */
typedef struct {
    /**
     * @brief Read string fields out of one object, in a single pass.
     *
     * @param[in]     json   Document bytes. NOT NUL-terminated.
     * @param[in]     len    Length of @c json.
     * @param[in]     object Name of the object to read from, or NULL for the document root.
     * @param[in,out] fields Fields to look up; outputs written in place.
     * @param[in]     num    Number of entries in @c fields.
     *
     * @return ESP_OK when the document parsed. An absent key is not an error:
     *         it reports @c found == false.
     */
    esp_err_t (*read_strs)(const char *json, size_t len, const char *object,
                           esp_rmaker_aws_sign_json_field_t fields[], size_t num);
} esp_rmaker_aws_sign_json_ops_t;

/* Log ************************************************************************/

typedef enum {
    ESP_RMAKER_AWS_SIGN_LOG_ERROR,
    ESP_RMAKER_AWS_SIGN_LOG_WARN,
    ESP_RMAKER_AWS_SIGN_LOG_INFO,
    ESP_RMAKER_AWS_SIGN_LOG_DEBUG,
} esp_rmaker_aws_sign_log_level_t;

/** Emit one already-formatted line; NULL discards all output. @c message is
 *  valid only for the duration of the call. */
typedef void (*esp_rmaker_aws_sign_log_fn_t)(esp_rmaker_aws_sign_log_level_t level, const char *tag,
                                             const char *message);

/* Port configuration *********************************************************/

/**
 * @brief The complete set of operations the component needs; copied by value at install.
 *
 * @note Do not call this component's API from an operation; operations run under its locks.
 */
typedef struct {
    esp_rmaker_aws_sign_mem_ops_t    mem;    /**< Required. */
    esp_rmaker_aws_sign_crypto_ops_t crypto; /**< Required. */
    esp_rmaker_aws_sign_time_ops_t   time;   /**< Required, but only get_time within it. */
    esp_rmaker_aws_sign_mutex_ops_t  mutex;  /**< Required when http is supplied. */
    esp_rmaker_aws_sign_http_ops_t   http;   /**< Optional; all-NULL disables creds + signed requests. */
    esp_rmaker_aws_sign_json_ops_t   json;   /**< Required when http is supplied. */
    esp_rmaker_aws_sign_log_fn_t     log;    /**< Optional; NULL discards all output. */
} esp_rmaker_aws_sign_port_config_t;

/**
 * @brief Install the default ESP-IDF port, once for the whole process.
 *
 * @note Links port/esp and its dependencies; esp_rmaker_aws_sign_port_install() links none of them.
 */
esp_err_t esp_rmaker_aws_sign_port_install_default(void);

/**
 * @brief Install a caller-supplied port, once for the whole process.
 *
 * @return ESP_OK if this port, or an identical one, is installed.
 *         ESP_ERR_INVALID_STATE if a different port is already installed.
 *         ESP_ERR_NOT_FINISHED if another install runs now.
 */
esp_err_t esp_rmaker_aws_sign_port_install(const esp_rmaker_aws_sign_port_config_t *port);

/** @brief Report whether a port is installed. */
bool esp_rmaker_aws_sign_port_is_installed(void);

/* Identity handle ************************************************************/

/** Credential-provider identity. Copied into the handle at create. */
typedef struct {
    const char *cred_host;        /**< e.g. "c1abcdef.credentials.iot.us-east-1.amazonaws.com" */
    const char *thing_name;       /**< sent as x-amzn-iot-thingname */
    const char *client_cert;      /**< PEM (NUL-terminated) or DER */
    size_t      client_cert_len;  /**< 0 => PEM, derive strlen()+1 */
    const char *client_key;
    size_t      client_key_len;
    const char *region;           /**< NULL => parse from cred_host */
} esp_rmaker_aws_sign_config_t;

/** Temporary credentials from the IoT Credential Provider. Caller-owned and zeroed before the
 *  first refresh; only this component fills it, and esp_rmaker_aws_sign_creds_free() releases it. */
typedef struct {
    char    *access_key_id;
    char    *secret_access_key;
    char    *session_token;
    int64_t  expiration_epoch_sec;
    int64_t  refresh_epoch_sec;   /**< when the next refresh fetches again; internal */
    uint32_t host_gen;            /**< credential host the strings came from; internal */
    uint32_t alias_hash;          /**< role alias the strings came from; internal */
} esp_rmaker_aws_sign_creds_t;

/** Caller-owned identity: config copy, credential host and pooled connection. */
typedef struct esp_rmaker_aws_sign_ctx *esp_rmaker_aws_sign_handle_t;

/**
 * @brief Create a handle for the credential and signed-request layers.
 *
 * @return ESP_ERR_INVALID_STATE if no port is installed.
 *         ESP_ERR_NOT_SUPPORTED if the port has no http ops.
 */
esp_err_t esp_rmaker_aws_sign_create(const esp_rmaker_aws_sign_config_t *config,
                                     esp_rmaker_aws_sign_handle_t *out);

/**
 * @brief Release @c handle, its config copy and its pooled connection.
 *
 * @note No other task may be inside a call on @c handle.
 * @note Do not use @c handle after this call.
 */
void esp_rmaker_aws_sign_destroy(esp_rmaker_aws_sign_handle_t handle);

/**
 * @brief Change the credential host; a NULL @c region is parsed from @c cred_host.
 *
 * @note Every credentials struct of @c handle fetches again on its next refresh.
 */
esp_err_t esp_rmaker_aws_sign_set_cred_host(esp_rmaker_aws_sign_handle_t handle,
                                            const char *cred_host, const char *region);

/** @brief Copy the region in use into @c buf. */
esp_err_t esp_rmaker_aws_sign_get_region(esp_rmaker_aws_sign_handle_t handle,
                                         char *buf, size_t buf_len);

/**
 * @brief Fetch credentials into @c creds when it is empty, near expiry, or from another host.
 *
 * @note One struct per role alias; tasks share one only through send_request() on one handle. 6-8 KB stack.
 *
 * @return ESP_OK with @c creds current; on any error, @c creds keeps its old contents.
 *         ESP_ERR_INVALID_STATE if the clock is not trustworthy, with no network I/O.
 *         ESP_ERR_INVALID_ARG if @c handle is not valid, or @c creds holds another role alias.
 */
esp_err_t esp_rmaker_aws_sign_creds_refresh(esp_rmaker_aws_sign_handle_t handle,
                                            const char *role_alias,
                                            esp_rmaker_aws_sign_creds_t *creds);

/** @brief Release the strings in @c creds and zero it. */
void esp_rmaker_aws_sign_creds_free(esp_rmaker_aws_sign_creds_t *creds);

/* Low-level SigV4 signer (service/region-generic) *****************************/

typedef struct {
    const char *name;
    const char *value;
} esp_rmaker_aws_sign_header_t;

/** A RAW query parameter; the component encodes and sorts it. */
typedef struct {
    const char *name;
    const char *value;            /**< NULL => empty, as for a subresource like "acl" */
} esp_rmaker_aws_sign_query_param_t;

typedef struct {
    const char *method;           /**< uppercase; see esp_rmaker_aws_sign_method_supported() */
    const char *host;
    const char *path;             /**< RAW absolute path, begins with '/'; the signer encodes it */
    const esp_rmaker_aws_sign_query_param_t *params;   /**< RAW and unsorted; may be NULL */
    size_t      params_count;
    const esp_rmaker_aws_sign_header_t *headers;
    size_t      headers_count;
    const uint8_t *payload;       /**< NULL for empty */
    size_t      payload_len;
    const char *payload_hash_hex; /**< optional override: precomputed hex, or "UNSIGNED-PAYLOAD" */
    bool        sign_payload_hash; /**< also sign x-amz-content-sha256: the payload hash */
    const char *access_key_id;
    const char *secret_access_key;
    const char *session_token;    /**< may be NULL */
    const char *region;
    const char *service;          /**< "execute-api" "s3" "kinesisvideo" … */
    int64_t     now_epoch_sec;    /**< trusted verbatim, NOT gated on time sync */
} esp_rmaker_aws_sign_sigv4_input_t;

typedef struct {
    char *authorization_header;   /**< full "AWS4-HMAC-SHA256 …" value */
    char *amz_date;               /**< "YYYYMMDDTHHMMSSZ" — also send as x-amz-date */
    char *content_sha256;         /**< hex SHA256 of payload — x-amz-content-sha256 */
} esp_rmaker_aws_sign_sigv4_output_t;

/**
 * @brief Sign one request.
 *
 * @note Needs mem, crypto and time ops but no networking. Release @c out with
 *       esp_rmaker_aws_sign_sigv4_output_free().
 */
esp_err_t esp_rmaker_aws_sign_sigv4(const esp_rmaker_aws_sign_sigv4_input_t *in,
                                    esp_rmaker_aws_sign_sigv4_output_t *out);

void esp_rmaker_aws_sign_sigv4_output_free(esp_rmaker_aws_sign_sigv4_output_t *out);

typedef struct {
    const char *scheme;           /**< "https" or "wss"; NULL => "https" */
    const char *method;
    const char *host;
    const char *path;             /**< RAW absolute path, begins with '/' */
    const esp_rmaker_aws_sign_query_param_t *params;   /**< RAW and unsorted; may be NULL */
    size_t      params_count;
    const esp_rmaker_aws_sign_header_t *headers;       /**< signed besides host; caller sends them */
    size_t      headers_count;
    const char *payload_hash_hex; /**< NULL => "UNSIGNED-PAYLOAD" for s3, else the empty hash */
    uint32_t    expires_sec;      /**< 1 to 604800 */
    const char *access_key_id;
    const char *secret_access_key;
    const char *session_token;    /**< may be NULL */
    bool        token_after_signature; /**< append the token unsigned, as AWS IoT WebSockets needs */
    const char *region;
    const char *service;
    int64_t     now_epoch_sec;    /**< trusted verbatim, NOT gated on time sync */
} esp_rmaker_aws_sign_presign_input_t;

/**
 * @brief Build a URL with the SigV4 signature in its query string.
 *
 * @note Release @c *url with esp_rmaker_aws_sign_free().
 */
esp_err_t esp_rmaker_aws_sign_presign_url(const esp_rmaker_aws_sign_presign_input_t *in,
                                          char **url);

/* High-level: sign + send one request ****************************************/

typedef struct {
    const char *method;
    const char *host;
    const char *path;             /**< RAW absolute path; encoded for the URL and the signature */
    const esp_rmaker_aws_sign_query_param_t *params;   /**< RAW and unsorted; may be NULL */
    size_t      params_count;
    const char *service;
    const char *region;           /**< NULL => the credential host's region */
    const char *role_alias;
    esp_rmaker_aws_sign_creds_t *creds;  /**< caller-owned; refreshed in place for @c role_alias */
    /** Content-Type defaults to "application/json" when a payload
     *  is present and none is given here. */
    const esp_rmaker_aws_sign_header_t *extra_headers;
    size_t      extra_headers_count;
    const uint8_t *payload;
    size_t      payload_len;
    int         timeout_ms;       /**< 0 => default; a change opens a new connection */
} esp_rmaker_aws_sign_request_t;

typedef struct {
    int      status_code;
    uint8_t *body;
    size_t   body_len;
} esp_rmaker_aws_sign_response_t;

/**
 * @brief Refresh @c req->creds, sign and send one request over HTTPS.
 *
 * @note Blocking. Release @c resp with esp_rmaker_aws_sign_response_free().
 */
esp_err_t esp_rmaker_aws_sign_send_request(esp_rmaker_aws_sign_handle_t handle,
                                           const esp_rmaker_aws_sign_request_t *req,
                                           esp_rmaker_aws_sign_response_t *resp);

void esp_rmaker_aws_sign_response_free(esp_rmaker_aws_sign_response_t *resp);

/**
 * @brief Report whether esp_rmaker_aws_sign_send_request() accepts @c method.
 *
 * @note Lets a caller reject an unsupported method up front, rather than duplicating the list.
 */
bool esp_rmaker_aws_sign_method_supported(const char *method);

/**
 * @brief "…iot.us-east-1.amazonaws.com" -> "us-east-1". NULL on failure.
 *
 * @note Port-allocated, so release it with esp_rmaker_aws_sign_free().
 */
char *esp_rmaker_aws_sign_parse_region_from_host(const char *host);

/** @brief Release memory handed back by this component's port allocator. */
void esp_rmaker_aws_sign_free(void *ptr);

#ifdef __cplusplus
}
#endif
