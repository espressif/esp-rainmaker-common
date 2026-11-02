/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file esp_rmaker_aws_sign_sigv4.c
 * @brief The SigV4 signer.
 *
 * @note The canonical request is streamed into the digest, never materialised,
 *       so signing costs under 1 KB of stack.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "esp_rmaker_aws_sign_internal.h"

#define SHA256_LEN   32
#define HEX_LEN      (SHA256_LEN * 2)
#define MAX_HEADERS  16
#define SCOPE_LEN    128
#define STS_LEN      320
#define AKEY_LEN     132

static const char *TAG = "esp_rmaker_aws_sign_sigv4";

static const char HEXL[] = "0123456789abcdef";
static const char HEXU[] = "0123456789ABCDEF";

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEXL[in[i] >> 4];
        out[2 * i + 1] = HEXL[in[i] & 0xF];
    }
    out[2 * n] = '\0';
}

char *esp_rmaker_aws_sign_strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *copy = AWS_CALLOC(1, n);
    if (copy) {
        memcpy(copy, s, n);
    }
    return copy;
}

void esp_rmaker_aws_sign_free(void *ptr)
{
    if (ptr && esp_rmaker_aws_sign_port_is_installed()) {
        AWS_FREE(ptr);
    }
}

/* Output sink ****************************************************************
 *
 * One encoder serves both the signer, which streams into the digest, and the
 * buffer-writing helpers the tests drive, so the two cannot disagree. */

typedef struct {
    esp_rmaker_aws_sign_sha256_ctx_t ctx;   /**< digest mode */
    char       *dst;                        /**< buffer mode */
    size_t      cap;
    size_t      len;                        /**< bytes the full output needs, excluding NUL */
    bool        hashing;
    esp_err_t   err;
} aws_out_t;

static esp_err_t out_hash_init(aws_out_t *o)
{
    memset(o, 0, sizeof(*o));
    o->hashing = true;
    /* Zeroed above so sha256_abort() is safe before init succeeds. */
    o->err = AWS_CRYPTO->sha256_init(&o->ctx);
    return o->err;
}

static void out_buf_init(aws_out_t *o, char *dst, size_t cap)
{
    memset(o, 0, sizeof(*o));
    o->dst = dst;
    o->cap = cap;
}

static void out_put(aws_out_t *o, const void *p, size_t n)
{
    if (o->hashing) {
        if (o->err == ESP_OK) {
            o->err = AWS_CRYPTO->sha256_update(&o->ctx, (const uint8_t *)p, n);
        }
        return;
    }
    if (o->dst && o->cap && o->len + n < o->cap) {
        memcpy(o->dst + o->len, p, n);
    }
    o->len += n;
}

static void out_putc(aws_out_t *o, char c)
{
    out_put(o, &c, 1);
}

static void out_puts(aws_out_t *o, const char *s)
{
    out_put(o, s, strlen(s));
}

static size_t out_buf_finish(aws_out_t *o)
{
    if (o->dst && o->cap) {
        o->dst[o->len < o->cap ? o->len : o->cap - 1] = '\0';
    }
    return o->len;
}

static esp_err_t out_hash_finish(aws_out_t *o, uint8_t out[SHA256_LEN])
{
    if (o->err != ESP_OK) {
        AWS_CRYPTO->sha256_abort(&o->ctx);
        return o->err;
    }
    return AWS_CRYPTO->sha256_finish(&o->ctx, out);
}

/* The one-shot digest the port does not provide. One call site: the payload. */
static esp_err_t aws_sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_LEN])
{
    aws_out_t o;
    if (out_hash_init(&o) != ESP_OK) {
        return ESP_FAIL;
    }
    out_put(&o, data, len);
    return out_hash_finish(&o, out);
}

/* Encoders *******************************************************************/

/* RFC 3986: unreserved passes through, everything else becomes uppercase %XX.
 * Double-encoding only adds "%25" for "%", since hex digits are unreserved. */
static void put_encoded_n(aws_out_t *o, const char *src, size_t len, bool keep_slash, bool twice)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~'
                || (keep_slash && c == '/')) {
            out_putc(o, (char)c);
            continue;
        }
        out_puts(o, twice ? "%25" : "%");
        out_putc(o, HEXU[c >> 4]);
        out_putc(o, HEXU[c & 0xF]);
    }
}

static void put_encoded(aws_out_t *o, const char *src, bool keep_slash, bool twice)
{
    put_encoded_n(o, src, strlen(src), keep_slash, twice);
}

/* A path: as put_encoded(), but an empty one is "/". */
static void put_uri(aws_out_t *o, const char *src, bool keep_slash, bool twice)
{
    if (*src == '\0') {
        out_putc(o, '/');
        return;
    }
    put_encoded(o, src, keep_slash, twice);
}

typedef enum { SEG_END, SEG_NAME, SEG_DOT, SEG_DOT_DOT } seg_kind_t;

/* Advance *p past slashes and one segment, and classify it. */
static seg_kind_t next_segment(const char **p, const char **seg, size_t *len)
{
    while (**p == '/') {
        (*p)++;
    }
    *seg = *p;
    while (**p && **p != '/') {
        (*p)++;
    }
    *len = (size_t)(*p - *seg);
    if (*len == 0) {
        return SEG_END;
    }
    if (*len == 1 && (*seg)[0] == '.') {
        return SEG_DOT;
    }
    if (*len == 2 && (*seg)[0] == '.' && (*seg)[1] == '.') {
        return SEG_DOT_DOT;
    }
    return SEG_NAME;
}

/* A ".." removes the nearest name before it still present; true if one in @c rest removes ours. */
static bool removed_later(const char *rest)
{
    int names = 0;
    const char *seg;
    size_t len;
    for (seg_kind_t k; (k = next_segment(&rest, &seg, &len)) != SEG_END;) {
        if (k == SEG_NAME) {
            names++;
        } else if (k == SEG_DOT_DOT && --names < 0) {
            return true;
        }
    }
    return false;
}

/* RFC 3986 5.2.4 plus empty-segment removal, as SigV4 wants for a non-S3 path. No buffer. */
static void put_normalized(aws_out_t *o, const char *path, bool encode)
{
    bool any = false;
    const char *p = path, *seg;
    size_t len;
    for (seg_kind_t k; (k = next_segment(&p, &seg, &len)) != SEG_END;) {
        if (k != SEG_NAME || removed_later(p)) {
            continue;
        }
        out_putc(o, '/');
        if (encode) {
            put_encoded_n(o, seg, len, true, true);
        } else {
            out_put(o, seg, len);
        }
        any = true;
    }
    if (!any || path[strlen(path) - 1] == '/') {
        out_putc(o, '/');
    }
}

/* Strip surrounding whitespace, collapse internal runs to one space. The
 * quoted-string exemption is not implemented; no signed request needs it. */
static void put_trimmed(aws_out_t *o, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    while (*p && isspace(*p)) {
        p++;
    }
    bool pending_space = false;
    for (; *p; p++) {
        if (isspace(*p)) {
            pending_space = true;
            continue;
        }
        if (pending_space) {
            out_putc(o, ' ');
            pending_space = false;
        }
        out_putc(o, (char)*p);
    }
}

static void put_lower(aws_out_t *o, const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        out_putc(o, (char)tolower(*p));
    }
}

size_t esp_rmaker_aws_sign_uri_encode_into(char *dst, size_t cap, const char *src,
                                           bool keep_slash, bool twice)
{
    aws_out_t o;
    out_buf_init(&o, dst, cap);
    put_uri(&o, src, keep_slash, twice);
    return out_buf_finish(&o);
}

size_t esp_rmaker_aws_sign_normalize_path_into(char *dst, size_t cap, const char *src)
{
    aws_out_t o;
    out_buf_init(&o, dst, cap);
    put_normalized(&o, src, false);
    return out_buf_finish(&o);
}

size_t esp_rmaker_aws_sign_trim_header_value(char *dst, size_t cap, const char *src)
{
    aws_out_t o;
    out_buf_init(&o, dst, cap);
    put_trimmed(&o, src);
    return out_buf_finish(&o);
}

/* Headers ********************************************************************/

/* A caller copy of a header the signer adds, or of Authorization, would not match the wire. */
static bool name_reserved(const esp_rmaker_aws_sign_header_t *builtin, int n, const char *name)
{
    if (strcasecmp(name, "authorization") == 0) {
        return true;
    }
    for (int i = 0; i < n; i++) {
        if (strcasecmp(builtin[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

/* Copy the signer's own headers, then the caller's, and stable-sort by
 * lowercased name: duplicates join their values in insertion order. */
static int collect_headers(const esp_rmaker_aws_sign_header_t *builtin, int n_builtin,
                           const esp_rmaker_aws_sign_header_t *extra, size_t n_extra,
                           esp_rmaker_aws_sign_header_t *h)
{
    int n = 0;
    for (; n < n_builtin; n++) {
        h[n] = builtin[n];
    }
    for (size_t i = 0; i < n_extra; i++) {
        if (n >= MAX_HEADERS) {
            return -1;                      /* caller error, not a silent truncation */
        }
        if (extra[i].name == NULL || extra[i].value == NULL
                || name_reserved(builtin, n_builtin, extra[i].name)) {
            return -1;
        }
        h[n++] = extra[i];
    }
    /* Insertion sort: stable, and N is tiny. */
    for (int i = 1; i < n; i++) {
        esp_rmaker_aws_sign_header_t key = h[i];
        int j = i - 1;
        while (j >= 0 && strcasecmp(h[j].name, key.name) > 0) {
            h[j + 1] = h[j];
            j--;
        }
        h[j + 1] = key;
    }
    return n;
}

esp_err_t esp_rmaker_aws_sign_build_signed_headers(const esp_rmaker_aws_sign_header_t *sorted,
                                                   int n, char **out)
{
    if (!sorted || n <= 0 || !out) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t cap = 1;
    for (int i = 0; i < n; i++) {
        if (i && strcasecmp(sorted[i].name, sorted[i - 1].name) == 0) {
            continue;
        }
        cap += strlen(sorted[i].name) + 1;
    }
    char *joined = AWS_CALLOC(1, cap);
    if (!joined) {
        return ESP_ERR_NO_MEM;
    }
    aws_out_t o;
    out_buf_init(&o, joined, cap);
    for (int i = 0; i < n; i++) {
        if (i && strcasecmp(sorted[i].name, sorted[i - 1].name) == 0) {
            continue;
        }
        if (o.len) {
            out_putc(&o, ';');
        }
        put_lower(&o, sorted[i].name);
    }
    out_buf_finish(&o);
    *out = joined;
    return ESP_OK;
}

/* Canonical query ************************************************************/

typedef struct {
    char *name;
    char *value;
} enc_param_t;

static char *encode_dup(const char *s)
{
    aws_out_t o;
    out_buf_init(&o, NULL, 0);
    put_encoded(&o, s, false, false);
    size_t cap = o.len + 1;
    char *d = AWS_CALLOC(1, cap);
    if (d) {
        out_buf_init(&o, d, cap);
        put_encoded(&o, s, false, false);
        out_buf_finish(&o);
    }
    return d;
}

static int enc_param_cmp(const void *a, const void *b)
{
    const enc_param_t *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    return c ? c : strcmp(x->value, y->value);
}

esp_err_t esp_rmaker_aws_sign_build_query(const esp_rmaker_aws_sign_query_param_t *params,
                                          size_t count, char **out)
{
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!out || (count && !params)) {
        return ESP_ERR_INVALID_ARG;
    }
    *out = NULL;
    for (size_t i = 0; i < count; i++) {
        if (params[i].name == NULL) {
            return ESP_ERR_INVALID_ARG;
        }
    }
    if (count == 0) {
        return ESP_OK;
    }
    enc_param_t *enc = AWS_CALLOC(count, sizeof(enc_param_t));
    if (!enc) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = ESP_OK;
    size_t cap = 1;
    for (size_t i = 0; i < count; i++) {
        enc[i].name = encode_dup(params[i].name);
        enc[i].value = encode_dup(params[i].value ? params[i].value : "");
        if (!enc[i].name || !enc[i].value) {
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        cap += strlen(enc[i].name) + 1 + strlen(enc[i].value) + 1;
    }
    qsort(enc, count, sizeof(*enc), enc_param_cmp);
    char *joined = AWS_CALLOC(1, cap);
    if (!joined) {
        err = ESP_ERR_NO_MEM;
        goto out;
    }
    aws_out_t o;
    out_buf_init(&o, joined, cap);
    for (size_t i = 0; i < count; i++) {
        if (i) {
            out_putc(&o, '&');
        }
        out_puts(&o, enc[i].name);
        out_putc(&o, '=');
        out_puts(&o, enc[i].value);
    }
    out_buf_finish(&o);
    *out = joined;

out:
    for (size_t i = 0; i < count; i++) {
        AWS_FREE(enc[i].name);
        AWS_FREE(enc[i].value);
    }
    AWS_FREE(enc);
    return err;
}

/* The signer *****************************************************************/

void esp_rmaker_aws_sign_sigv4_output_free(esp_rmaker_aws_sign_sigv4_output_t *out)
{
    if (!out || !esp_rmaker_aws_sign_port_is_installed()) {
        return;
    }
    AWS_FREE(out->authorization_header);
    AWS_FREE(out->amz_date);
    AWS_FREE(out->content_sha256);
    memset(out, 0, sizeof(*out));
}

static esp_err_t make_amz_date(int64_t now_epoch_sec, char amz_date[17])
{
    time_t t = (time_t)now_epoch_sec;
    struct tm tm = {0};
    if (gmtime_r(&t, &tm) == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strftime(amz_date, 17, "%Y%m%dT%H%M%SZ", &tm) != 16) {     /* YYYYMMDDTHHMMSSZ */
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t make_scope(char scope[SCOPE_LEN], const char *amz_date, const char *region,
                            const char *service)
{
    int n = snprintf(scope, SCOPE_LEN, "%.8s/%s/%s/aws4_request", amz_date, region, service);
    return n > 0 && n < SCOPE_LEN ? ESP_OK : ESP_ERR_INVALID_ARG;
}

/* @c override may be "UNSIGNED-PAYLOAD", so it is copied verbatim. */
static esp_err_t make_payload_hash(const uint8_t *payload, size_t len, const char *override,
                                   char out[HEX_LEN + 1])
{
    if (override) {
        size_t n = strlen(override);
        if (n > HEX_LEN) {
            return ESP_ERR_INVALID_ARG;
        }
        memcpy(out, override, n + 1);
        return ESP_OK;
    }
    uint8_t ph[SHA256_LEN];
    /* Zero-length is valid and must yield e3b0c442… */
    if (aws_sha256(payload ? payload : (const uint8_t *)"", payload ? len : 0, ph) != ESP_OK) {
        AWS_LOGE(TAG, "Payload hash failed");
        return ESP_FAIL;
    }
    to_hex(ph, SHA256_LEN, out);
    return ESP_OK;
}

/* Everything the canonical request and the string to sign are built from. */
typedef struct {
    const char *method;
    const char *path;
    const char *query;            /* canonical, or NULL */
    const char *service;
    const char *region;
    const char *secret_access_key;
    const char *amz_date;
    const char *scope;
    const esp_rmaker_aws_sign_header_t *h;   /* sorted */
    int         n;
    const char *signed_headers;
    const char *payload_hex;
} creq_t;

/* Stream the canonical request into SHA-256, then derive the key and sign. */
static esp_err_t sign_canonical(const creq_t *r, char sig_hex[HEX_LEN + 1])
{
    bool is_s3 = strcmp(r->service, "s3") == 0;
    aws_out_t c;
    if (out_hash_init(&c) != ESP_OK) {
        return ESP_FAIL;
    }
    out_puts(&c, r->method);
    out_putc(&c, '\n');
    if (is_s3) {
        put_uri(&c, r->path, true, false);            /* S3 signs the path as given */
    } else {
        put_normalized(&c, r->path, true);            /* normalized, then encoded twice */
    }
    out_putc(&c, '\n');
    if (r->query) {
        out_puts(&c, r->query);
    }
    out_putc(&c, '\n');                               /* emitted even for an empty query */
    for (int i = 0; i < r->n;) {
        int j = i;
        put_lower(&c, r->h[i].name);
        out_putc(&c, ':');
        while (j < r->n && strcasecmp(r->h[j].name, r->h[i].name) == 0) {   /* join with ',' */
            if (j > i) {
                out_putc(&c, ',');
            }
            put_trimmed(&c, r->h[j].value);
            j++;
        }
        out_putc(&c, '\n');
        i = j;
    }
    out_putc(&c, '\n');                               /* blank line after CanonicalHeaders */
    out_puts(&c, r->signed_headers);
    out_putc(&c, '\n');
    out_puts(&c, r->payload_hex);                     /* no trailing newline */

    uint8_t creq_hash[SHA256_LEN];
    if (out_hash_finish(&c, creq_hash) != ESP_OK) {
        AWS_LOGE(TAG, "Canonical request hash failed");
        return ESP_FAIL;
    }
    char creq_hex[HEX_LEN + 1];
    to_hex(creq_hash, SHA256_LEN, creq_hex);

    /* String to sign: small and bounded, so built contiguously. */
    char sts[STS_LEN];
    int sts_len = snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                           r->amz_date, r->scope, creq_hex);
    if (sts_len <= 0 || sts_len >= (int)sizeof(sts)) {
        return ESP_FAIL;
    }

    /* Signing key. Ping-pong buffers: never alias HMAC in/out. */
    char akey[AKEY_LEN];
    if (snprintf(akey, sizeof(akey), "AWS4%s", r->secret_access_key) >= (int)sizeof(akey)) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_rmaker_aws_sign_crypto_ops_t *cr = AWS_CRYPTO;
    uint8_t k1[SHA256_LEN], k2[SHA256_LEN], sig[SHA256_LEN];
    esp_err_t ke = ESP_OK;
    ke |= cr->hmac_sha256((const uint8_t *)akey, strlen(akey), (const uint8_t *)r->amz_date, 8, k1);
    ke |= cr->hmac_sha256(k1, SHA256_LEN, (const uint8_t *)r->region, strlen(r->region), k2);
    ke |= cr->hmac_sha256(k2, SHA256_LEN, (const uint8_t *)r->service, strlen(r->service), k1);
    ke |= cr->hmac_sha256(k1, SHA256_LEN, (const uint8_t *)"aws4_request", 12, k2);
    ke |= cr->hmac_sha256(k2, SHA256_LEN, (const uint8_t *)sts, (size_t)sts_len, sig);
    to_hex(sig, SHA256_LEN, sig_hex);

    aws_zeroize(akey, sizeof(akey));
    aws_zeroize(k1, sizeof(k1));
    aws_zeroize(k2, sizeof(k2));
    if (ke != ESP_OK) {
        AWS_LOGE(TAG, "Signing key derivation failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t esp_rmaker_aws_sign_sigv4(const esp_rmaker_aws_sign_sigv4_input_t *in,
                                    esp_rmaker_aws_sign_sigv4_output_t *out)
{
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!in) {
        return ESP_ERR_INVALID_ARG;
    }
    char *query = NULL;
    esp_err_t err = esp_rmaker_aws_sign_build_query(in->params, in->params_count, &query);
    if (err == ESP_OK) {
        err = esp_rmaker_aws_sign_sigv4_with_query(in, query, out);
    }
    AWS_FREE(query);
    return err;
}

esp_err_t esp_rmaker_aws_sign_sigv4_with_query(const esp_rmaker_aws_sign_sigv4_input_t *in,
                                               const char *query,
                                               esp_rmaker_aws_sign_sigv4_output_t *out)
{
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!in || !out || !in->method || !in->host || !in->path || in->path[0] != '/'
            || !in->access_key_id || !in->secret_access_key || !in->region || !in->service
            || (in->headers_count && !in->headers) || (in->payload_len && !in->payload)) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char amz_date[17], scope[SCOPE_LEN], payload_hex[HEX_LEN + 1];
    esp_err_t err = make_amz_date(in->now_epoch_sec, amz_date);
    if (err == ESP_OK) {
        err = make_scope(scope, amz_date, in->region, in->service);
    }
    if (err == ESP_OK) {
        err = make_payload_hash(in->payload, in->payload_len, in->payload_hash_hex, payload_hex);
    }
    if (err != ESP_OK) {
        return err;
    }

    esp_rmaker_aws_sign_header_t builtin[4];
    int n_builtin = 0;
    builtin[n_builtin++] = (esp_rmaker_aws_sign_header_t) { "host", in->host };
    builtin[n_builtin++] = (esp_rmaker_aws_sign_header_t) { "x-amz-date", amz_date };
    if (in->session_token) {
        builtin[n_builtin++] = (esp_rmaker_aws_sign_header_t) {
            "x-amz-security-token", in->session_token
        };
    }
    if (in->sign_payload_hash) {
        builtin[n_builtin++] = (esp_rmaker_aws_sign_header_t) { "x-amz-content-sha256", payload_hex };
    }
    esp_rmaker_aws_sign_header_t h[MAX_HEADERS];
    int n = collect_headers(builtin, n_builtin, in->headers, in->headers_count, h);
    if (n < 0) {
        AWS_LOGE(TAG, "Too many headers, a NULL name/value, or a reserved header name");
        return ESP_ERR_INVALID_ARG;
    }
    char *signed_headers = NULL;
    err = esp_rmaker_aws_sign_build_signed_headers(h, n, &signed_headers);
    if (err != ESP_OK) {
        return err;
    }

    const creq_t r = {
        .method = in->method, .path = in->path, .query = query, .service = in->service,
        .region = in->region, .secret_access_key = in->secret_access_key,
        .amz_date = amz_date, .scope = scope, .h = h, .n = n,
        .signed_headers = signed_headers, .payload_hex = payload_hex,
    };
    char sig_hex[HEX_LEN + 1];
    err = sign_canonical(&r, sig_hex);
    if (err != ESP_OK) {
        AWS_FREE(signed_headers);
        return err;
    }

    size_t cap = strlen("AWS4-HMAC-SHA256 Credential=") + strlen(in->access_key_id) + 1
                 + strlen(scope) + strlen(", SignedHeaders=") + strlen(signed_headers)
                 + strlen(", Signature=") + HEX_LEN + 1;
    out->authorization_header = AWS_CALLOC(1, cap);
    if (out->authorization_header) {
        snprintf(out->authorization_header, cap,
                 "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
                 in->access_key_id, scope, signed_headers, sig_hex);
    }
    out->amz_date = esp_rmaker_aws_sign_strdup(amz_date);
    out->content_sha256 = esp_rmaker_aws_sign_strdup(payload_hex);
    AWS_FREE(signed_headers);

    if (!out->authorization_header || !out->amz_date || !out->content_sha256) {
        esp_rmaker_aws_sign_sigv4_output_free(out);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/* Presigned URL **************************************************************/

#define PRESIGN_MAX_EXPIRES 604800          /* seven days, the SigV4 limit */
#define PRESIGN_OWN_PARAMS  6

/* Names presign adds itself; a caller copy would break the signature. */
static bool presign_param_reserved(const char *name)
{
    static const char *const own[] = {
        "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
        "X-Amz-SignedHeaders", "X-Amz-Security-Token", "X-Amz-Signature",
    };
    for (size_t i = 0; i < sizeof(own) / sizeof(own[0]); i++) {
        if (strcasecmp(name, own[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void put_presigned_url(aws_out_t *o, const esp_rmaker_aws_sign_presign_input_t *in,
                              const char *query, const char *sig_hex)
{
    out_puts(o, in->scheme ? in->scheme : "https");
    out_puts(o, "://");
    out_puts(o, in->host);
    put_uri(o, in->path, true, false);
    out_putc(o, '?');
    out_puts(o, query);
    out_puts(o, "&X-Amz-Signature=");
    out_puts(o, sig_hex);
    if (in->session_token && in->token_after_signature) {
        out_puts(o, "&X-Amz-Security-Token=");
        put_encoded(o, in->session_token, false, false);
    }
}

esp_err_t esp_rmaker_aws_sign_presign_url(const esp_rmaker_aws_sign_presign_input_t *in,
                                          char **url)
{
    if (!esp_rmaker_aws_sign_port_is_installed()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!in || !url || !in->method || !in->host || !in->path || in->path[0] != '/'
            || !in->access_key_id || !in->secret_access_key || !in->region || !in->service
            || (in->params_count && !in->params) || (in->headers_count && !in->headers)
            || in->expires_sec == 0 || in->expires_sec > PRESIGN_MAX_EXPIRES) {
        return ESP_ERR_INVALID_ARG;
    }
    *url = NULL;
    for (size_t i = 0; i < in->params_count; i++) {
        if (in->params[i].name == NULL || presign_param_reserved(in->params[i].name)) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    char amz_date[17], scope[SCOPE_LEN], payload_hex[HEX_LEN + 1], expires[12];
    bool is_s3 = strcmp(in->service, "s3") == 0;
    esp_err_t err = make_amz_date(in->now_epoch_sec, amz_date);
    if (err == ESP_OK) {
        err = make_scope(scope, amz_date, in->region, in->service);
    }
    if (err == ESP_OK) {
        const char *override = in->payload_hash_hex ? in->payload_hash_hex
                               : is_s3 ? "UNSIGNED-PAYLOAD" : NULL;
        err = make_payload_hash(NULL, 0, override, payload_hex);
    }
    if (err != ESP_OK) {
        return err;
    }
    snprintf(expires, sizeof(expires), "%u", (unsigned)in->expires_sec);

    const esp_rmaker_aws_sign_header_t host = { "host", in->host };
    esp_rmaker_aws_sign_header_t h[MAX_HEADERS];
    int n = collect_headers(&host, 1, in->headers, in->headers_count, h);
    if (n < 0) {
        AWS_LOGE(TAG, "Too many headers, a NULL name/value, or a reserved header name");
        return ESP_ERR_INVALID_ARG;
    }

    char *signed_headers = NULL, *credential = NULL, *query = NULL;
    esp_rmaker_aws_sign_query_param_t *params = NULL;
    err = esp_rmaker_aws_sign_build_signed_headers(h, n, &signed_headers);
    if (err != ESP_OK) {
        return err;
    }
    size_t cred_len = strlen(in->access_key_id) + 1 + strlen(scope) + 1;
    credential = AWS_CALLOC(1, cred_len);
    params = AWS_CALLOC(in->params_count + PRESIGN_OWN_PARAMS,
                        sizeof(esp_rmaker_aws_sign_query_param_t));
    if (!credential || !params) {
        err = ESP_ERR_NO_MEM;
        goto out;
    }
    snprintf(credential, cred_len, "%s/%s", in->access_key_id, scope);

    size_t np = 0;
    for (; np < in->params_count; np++) {
        params[np] = in->params[np];
    }
    params[np++] = (esp_rmaker_aws_sign_query_param_t) { "X-Amz-Algorithm", "AWS4-HMAC-SHA256" };
    params[np++] = (esp_rmaker_aws_sign_query_param_t) { "X-Amz-Credential", credential };
    params[np++] = (esp_rmaker_aws_sign_query_param_t) { "X-Amz-Date", amz_date };
    params[np++] = (esp_rmaker_aws_sign_query_param_t) { "X-Amz-Expires", expires };
    params[np++] = (esp_rmaker_aws_sign_query_param_t) { "X-Amz-SignedHeaders", signed_headers };
    if (in->session_token && !in->token_after_signature) {
        params[np++] = (esp_rmaker_aws_sign_query_param_t) {
            "X-Amz-Security-Token", in->session_token
        };
    }
    err = esp_rmaker_aws_sign_build_query(params, np, &query);
    if (err != ESP_OK) {
        goto out;
    }

    const creq_t r = {
        .method = in->method, .path = in->path, .query = query, .service = in->service,
        .region = in->region, .secret_access_key = in->secret_access_key,
        .amz_date = amz_date, .scope = scope, .h = h, .n = n,
        .signed_headers = signed_headers, .payload_hex = payload_hex,
    };
    char sig_hex[HEX_LEN + 1];
    err = sign_canonical(&r, sig_hex);
    if (err != ESP_OK) {
        goto out;
    }

    aws_out_t o;
    out_buf_init(&o, NULL, 0);
    put_presigned_url(&o, in, query, sig_hex);
    size_t cap = o.len + 1;
    *url = AWS_CALLOC(1, cap);
    if (!*url) {
        err = ESP_ERR_NO_MEM;
        goto out;
    }
    out_buf_init(&o, *url, cap);
    put_presigned_url(&o, in, query, sig_hex);
    out_buf_finish(&o);

out:
    AWS_FREE(signed_headers);
    AWS_FREE(credential);
    AWS_FREE(params);
    AWS_FREE(query);
    return err;
}
