/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* The credential and signed-request layers driven through a recording HTTP stub,
 * so the refresh margin, the connection pool and the emitted headers
 * are all observable without a network. The ESP port runs against a loopback server. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"
#include "esp_rmaker_aws_sign_internal.h"
#include "test_aws_sign.h"

#define CRED_HOST   "c1abcdef.credentials.iot.us-east-1.amazonaws.com"
#define THING_NAME  "node1234"
#define API_HOST    "api.execute-api.us-east-1.amazonaws.com"
#define OTHER_HOST  "other.execute-api.us-east-1.amazonaws.com"
#define NOW         1440938160          /* 20150830T123600Z */
#define CRED_TTL    86400
#define CRED_EXPIRY "2015-08-31T12:36:00Z"     /* NOW + CRED_TTL */
#define STALE       "2001-01-01T00:00:00Z"     /* well before NOW */
#define NEAR_EXPIRY "2015-08-30T12:52:40Z"     /* NOW + NEAR_TTL */
#define NEAR_TTL    1000
#define SHORT_EXPIRY "2015-08-30T12:38:00Z"    /* NOW + SHORT_TTL */
#define SHORT_TTL   120

#define CREDS_JSON(exp) \
    "{\"credentials\":{\"accessKeyId\":\"AK\",\"secretAccessKey\":\"SK\"," \
    "\"sessionToken\":\"TOK\",\"expiration\":\"" exp "\"}}"

#define EMPTY_PAYLOAD_HASH "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define BODY_PAYLOAD_HASH  "5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22"

#define MAX_REC_HEADERS 12
#define HANDLE          ((esp_rmaker_aws_sign_http_handle_t)0xF00D)

typedef struct {
    char name[40];
    char value[512];
} rec_header_t;

static struct {
    int opens, closes, performs, set_urls;
    char url[256];
    esp_rmaker_aws_sign_http_method_t method;
    bool keep_alive;
    int timeout_ms;
    const char *cert;
    rec_header_t headers[MAX_REC_HEADERS];
    int header_count;
    rec_header_t sent[MAX_REC_HEADERS];     /* snapshot taken when the request goes out */
    int sent_count;
    char body[64];
    size_t body_len;
    const char *resp;               /* scripted response body, for every other URL */
    size_t resp_len;
    const char *cred_resp;          /* scripted response body, for a credential URL */
    size_t cred_resp_len;
    bool chunked;                   /* declare no length, as a chunked response does */
    bool fail_after_hint;           /* fail once the response has started, as a dropped read does */
    void (*on_perform)(void);       /* test-only probe; real ports must not call the API */
    int status;
    esp_err_t open_err, perform_err;
} s_http;

static int64_t s_now;
static bool s_synced;

/* Stub port ******************************************************************/

static time_t stub_get_time(time_t *p_time)
{
    if (p_time) {
        *p_time = (time_t)s_now;
    }
    return (time_t)s_now;
}

static bool stub_is_synced(void)
{
    return s_synced;
}

static esp_err_t stub_open(const esp_rmaker_aws_sign_http_config_t *cfg,
                           esp_rmaker_aws_sign_http_handle_t *out)
{
    if (s_http.open_err != ESP_OK) {
        return s_http.open_err;
    }
    s_http.opens++;
    s_http.header_count = 0;
    s_http.method = cfg->method;
    s_http.keep_alive = cfg->keep_alive;
    s_http.timeout_ms = cfg->timeout_ms;
    s_http.cert = cfg->client_cert;
    snprintf(s_http.url, sizeof(s_http.url), "%s", cfg->url);
    *out = HANDLE;
    return ESP_OK;
}

static esp_err_t stub_set_url(esp_rmaker_aws_sign_http_handle_t h, const char *url)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    s_http.set_urls++;
    snprintf(s_http.url, sizeof(s_http.url), "%s", url);
    return ESP_OK;
}

static esp_err_t stub_set_method(esp_rmaker_aws_sign_http_handle_t h,
                                 esp_rmaker_aws_sign_http_method_t method)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    s_http.method = method;
    return ESP_OK;
}

static esp_err_t stub_set_header(esp_rmaker_aws_sign_http_handle_t h, const char *name,
                                 const char *value)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    for (int i = 0; i < s_http.header_count; i++) {
        if (strcasecmp(s_http.headers[i].name, name) != 0) {
            continue;
        }
        if (value) {
            snprintf(s_http.headers[i].value, sizeof(s_http.headers[i].value), "%s", value);
        } else {
            s_http.headers[i] = s_http.headers[--s_http.header_count];   /* NULL removes it */
        }
        return ESP_OK;
    }
    if (!value) {
        return ESP_OK;
    }
    TEST_ASSERT_LESS_THAN(MAX_REC_HEADERS, s_http.header_count);
    rec_header_t *rec = &s_http.headers[s_http.header_count++];
    snprintf(rec->name, sizeof(rec->name), "%s", name);
    snprintf(rec->value, sizeof(rec->value), "%s", value);
    return ESP_OK;
}

/* Delivers the scripted body in short chunks, so the accumulating sink is
 * exercised the way a real transport drives it. */
static esp_err_t stub_perform(esp_rmaker_aws_sign_http_handle_t h, const uint8_t *body,
                              size_t body_len, const esp_rmaker_aws_sign_http_receiver_t *rx)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    TEST_ASSERT_NOT_NULL(rx);
    TEST_ASSERT_NOT_NULL(rx->sink);
    s_http.performs++;
    if (s_http.on_perform) {
        s_http.on_perform();
    }
    memcpy(s_http.sent, s_http.headers, sizeof(s_http.sent));
    s_http.sent_count = s_http.header_count;
    s_http.body_len = body_len < sizeof(s_http.body) ? body_len : sizeof(s_http.body);
    if (body && s_http.body_len) {
        memcpy(s_http.body, body, s_http.body_len);
    }
    if (s_http.perform_err != ESP_OK) {
        return s_http.perform_err;
    }
    bool to_creds = strstr(s_http.url, "/role-aliases/") != NULL;
    const char *resp = to_creds ? s_http.cred_resp : s_http.resp;
    size_t resp_len = to_creds ? s_http.cred_resp_len : s_http.resp_len;

    if (rx->hint && rx->hint(rx->ctx, s_http.chunked ? 0 : resp_len) != 0) {
        return ESP_FAIL;               /* the receiver refuses the declared size */
    }
    if (s_http.fail_after_hint) {
        return ESP_FAIL;
    }
    for (size_t off = 0; off < resp_len; off += 7) {
        size_t n = resp_len - off < 7 ? resp_len - off : 7;
        if (rx->sink(rx->ctx, (const uint8_t *)resp + off, n) != (int)n) {
            return ESP_FAIL;            /* a short read aborts the transfer */
        }
    }
    return ESP_OK;
}

static int stub_status_code(esp_rmaker_aws_sign_http_handle_t h)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    return s_http.status;
}

static void stub_close(esp_rmaker_aws_sign_http_handle_t h)
{
    TEST_ASSERT_EQUAL_PTR(HANDLE, h);
    s_http.closes++;
    s_http.header_count = 0;
}

static const char *header_value(const char *name)
{
    for (int i = 0; i < s_http.sent_count; i++) {
        if (strcasecmp(s_http.sent[i].name, name) == 0) {
            return s_http.sent[i].value;
        }
    }
    return NULL;
}

/* Fixture ********************************************************************/

/* The handle and the credentials every base_request() uses. */
static esp_rmaker_aws_sign_handle_t s_h;
static esp_rmaker_aws_sign_creds_t s_creds;

static void teardown(void)
{
    esp_rmaker_aws_sign_creds_free(&s_creds);
    esp_rmaker_aws_sign_destroy(s_h);
    s_h = NULL;
    esp_rmaker_aws_sign_port_uninstall();
}

static void install_http_port(const char *resp)
{
    teardown();
    memset(&s_http, 0, sizeof(s_http));
    s_http.status = 200;
    s_http.resp = resp;
    s_http.resp_len = resp ? strlen(resp) : 0;
    s_http.cred_resp = resp;
    s_http.cred_resp_len = s_http.resp_len;
    s_now = NOW;
    s_synced = true;

    esp_rmaker_aws_sign_port_config_t port = {
        .mem = esp_rmaker_aws_sign_esp_mem_ops,
        .crypto = esp_rmaker_aws_sign_esp_crypto_ops,
        .time = { .get_time = stub_get_time, .is_synced = stub_is_synced },
        .mutex = esp_rmaker_aws_sign_esp_mutex_ops,
        .http = {
            .open = stub_open, .set_url = stub_set_url, .set_method = stub_set_method,
            .set_header = stub_set_header, .perform = stub_perform,
            .status_code = stub_status_code, .close = stub_close,
        },
        .json = esp_rmaker_aws_sign_esp_json_ops,
        .log = esp_rmaker_aws_sign_esp_log,
    };
    esp_rmaker_aws_sign_config_t config = {
        .cred_host = CRED_HOST,
        .thing_name = THING_NAME,
        .client_cert = "-----BEGIN CERTIFICATE-----\n",
        .client_key = "-----BEGIN PRIVATE KEY-----\n",
    };
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_create(&config, &s_h));
}

static esp_rmaker_aws_sign_request_t base_request(const char *host)
{
    esp_rmaker_aws_sign_request_t req = {
        .method = "GET", .host = host, .path = "/prod/v1/things",
        .service = "execute-api", .role_alias = "alias", .creds = &s_creds,
    };
    return req;
}

/* Credentials ****************************************************************/

TEST_CASE("Credentials are fetched, then reused while fresh", "[aws_sign_http]")
{
    TEST_ASSERT_EQUAL_I64(NOW + CRED_TTL, esp_rmaker_aws_sign_iso8601_to_epoch(CRED_EXPIRY));
    install_http_port(CREDS_JSON(CRED_EXPIRY));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL_STRING("AK", s_creds.access_key_id);
    TEST_ASSERT_EQUAL_STRING("SK", s_creds.secret_access_key);
    TEST_ASSERT_EQUAL_STRING("TOK", s_creds.session_token);
    TEST_ASSERT_EQUAL_I64(NOW + CRED_TTL, s_creds.expiration_epoch_sec);

    TEST_ASSERT_EQUAL(1, s_http.opens);
    TEST_ASSERT_EQUAL(1, s_http.closes);
    TEST_ASSERT_EQUAL_STRING("https://" CRED_HOST "/role-aliases/alias/credentials", s_http.url);
    TEST_ASSERT_EQUAL(ESP_RMAKER_AWS_SIGN_HTTP_GET, s_http.method);
    TEST_ASSERT_FALSE(s_http.keep_alive);
    TEST_ASSERT_EQUAL(CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_HTTP_TIMEOUT_MS, s_http.timeout_ms);

    const char *first = s_creds.access_key_id;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL_PTR(first, s_creds.access_key_id);
    TEST_ASSERT_EQUAL(1, s_http.opens);

    teardown();
}

TEST_CASE("The credential request identifies the thing", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));

    TEST_ASSERT_EQUAL(1, s_http.performs);
    TEST_ASSERT_EQUAL(0, s_http.body_len);
    TEST_ASSERT_EQUAL_STRING(THING_NAME, header_value("x-amzn-iot-thingname"));
    TEST_ASSERT_EQUAL_STRING("application/json", header_value("Accept"));
    TEST_ASSERT_NULL(header_value("Authorization"));    /* mTLS is the identity here */
    TEST_ASSERT_EQUAL_STRING("-----BEGIN CERTIFICATE-----\n", s_http.cert);

    teardown();
}

TEST_CASE("Two structs hold two role aliases without refetching", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    esp_rmaker_aws_sign_creds_t other = {0};

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "other", &other));
    TEST_ASSERT_EQUAL(2, s_http.opens);
    TEST_ASSERT_EQUAL_STRING("https://" CRED_HOST "/role-aliases/other/credentials", s_http.url);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "other", &other));
    TEST_ASSERT_EQUAL(2, s_http.opens);

    esp_rmaker_aws_sign_creds_free(&other);
    TEST_ASSERT_NULL(other.access_key_id);
    teardown();
}

/* One second either side of the margin must decide differently. */
TEST_CASE("Credentials are refreshed only once inside the margin", "[aws_sign_http]")
{
    const int64_t expiry = NOW + NEAR_TTL;
    TEST_ASSERT_EQUAL_I64(expiry, esp_rmaker_aws_sign_iso8601_to_epoch(NEAR_EXPIRY));
    TEST_ASSERT_LESS_OR_EQUAL(NEAR_TTL / 2, CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC);

    install_http_port(CREDS_JSON(NEAR_EXPIRY));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    /* One second short of the margin: still fresh. */
    s_now = expiry - CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC - 1;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    /* On the margin: refetched. */
    s_now = expiry - CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);

    teardown();
}

/* Credentials that arrive inside the margin are not refetched on every call. */
TEST_CASE("Short-lived credentials are reused for half their lifetime", "[aws_sign_http]")
{
    TEST_ASSERT_EQUAL_I64(NOW + SHORT_TTL, esp_rmaker_aws_sign_iso8601_to_epoch(SHORT_EXPIRY));
    TEST_ASSERT_LESS_THAN(CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC, SHORT_TTL);

    install_http_port(CREDS_JSON(SHORT_EXPIRY));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    s_now = NOW + SHORT_TTL / 2 - 1;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    s_now = NOW + SHORT_TTL / 2;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);

    teardown();
}

TEST_CASE("A filled struct refuses another role alias", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      esp_rmaker_aws_sign_creds_refresh(s_h, "other", &s_creds));
    TEST_ASSERT_EQUAL_STRING("AK", s_creds.access_key_id);

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    req.role_alias = "other";
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    /* A freed struct is empty again, so it takes any alias. */
    esp_rmaker_aws_sign_creds_free(&s_creds);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "other", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);

    teardown();
}

TEST_CASE("A stale or absent expiry gets the fallback window", "[aws_sign_http]")
{
    install_http_port("{\"credentials\":{\"accessKeyId\":\"AK\",\"secretAccessKey\":\"SK\","
                      "\"sessionToken\":\"TOK\"}}");
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL_I64(NOW + CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_DEFAULT_TTL_SEC,
                          s_creds.expiration_epoch_sec);

    install_http_port(CREDS_JSON(STALE));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL_I64(NOW + CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_DEFAULT_TTL_SEC,
                          s_creds.expiration_epoch_sec);

    teardown();
}

TEST_CASE("A failed fetch fills nothing into an empty struct", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.status = 403;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);
    TEST_ASSERT_EQUAL(1, s_http.closes);

    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.open_err = ESP_FAIL;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);
    TEST_ASSERT_EQUAL(0, s_http.closes);

    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.perform_err = ESP_ERR_TIMEOUT;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);
    TEST_ASSERT_EQUAL(1, s_http.closes);

    install_http_port("");
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);

    teardown();
}

TEST_CASE("A failed refresh keeps the old credentials", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(NEAR_EXPIRY));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    const char *old = s_creds.access_key_id;

    s_now = NOW + NEAR_TTL - CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC;
    s_http.status = 503;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);
    TEST_ASSERT_EQUAL_PTR(old, s_creds.access_key_id);
    TEST_ASSERT_EQUAL_STRING("TOK", s_creds.session_token);

    teardown();
}

TEST_CASE("A new credential host forces a refetch", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    char region[ESP_RMAKER_AWS_SIGN_REGION_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("us-east-1", region);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    /* A host with no parseable region is refused, and changes nothing. */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      esp_rmaker_aws_sign_set_cred_host(s_h, "example.com", NULL));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      esp_rmaker_aws_sign_set_cred_host(s_h, NULL, "eu-west-1"));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(1, s_http.opens);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_set_cred_host(s_h,
                          "c2.credentials.iot.eu-west-1.amazonaws.com", NULL));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("eu-west-1", region);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);
    TEST_ASSERT_EQUAL_STRING(
        "https://c2.credentials.iot.eu-west-1.amazonaws.com/role-aliases/alias/credentials",
        s_http.url);

    /* An explicit region wins over the host. */
    TEST_ASSERT_EQUAL(ESP_OK,
                      esp_rmaker_aws_sign_set_cred_host(s_h, "creds.example.com", "ap-south-1"));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("ap-south-1", region);

    teardown();
}

TEST_CASE("Two handles are independent", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;
    const esp_rmaker_aws_sign_config_t config = {
        .cred_host = "c2.credentials.iot.eu-west-1.amazonaws.com",
        .thing_name = "kvs-client",
        .client_cert = "-----BEGIN CERTIFICATE-----\n",
        .client_key = "-----BEGIN PRIVATE KEY-----\n",
    };
    esp_rmaker_aws_sign_handle_t other = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_create(&config, &other));
    char region[ESP_RMAKER_AWS_SIGN_REGION_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(other, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("eu-west-1", region);

    /* A struct filled through one handle is fetched again through another. */
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(other, "alias", &s_creds));
    TEST_ASSERT_EQUAL(2, s_http.opens);
    TEST_ASSERT_EQUAL_STRING(
        "https://c2.credentials.iot.eu-west-1.amazonaws.com/role-aliases/alias/credentials",
        s_http.url);
    esp_rmaker_aws_sign_creds_free(&s_creds);

    /* Destroying one handle leaves the other usable. */
    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(other, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    esp_rmaker_aws_sign_destroy(other);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("us-east-1", region);

    teardown();
}

static char s_region_seen[ESP_RMAKER_AWS_SIGN_REGION_LEN];
static esp_err_t s_region_err;

static void read_region(void)
{
    s_region_err = esp_rmaker_aws_sign_get_region(s_h, s_region_seen, sizeof(s_region_seen));
}

/* On one task, a lock on a mutex the fetch or the request holds would never return. */
TEST_CASE("The region is readable during a fetch and a signed request", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.on_perform = read_region;

    s_region_err = ESP_FAIL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(ESP_OK, s_region_err);
    TEST_ASSERT_EQUAL_STRING("us-east-1", s_region_seen);

    s_region_err = ESP_FAIL;
    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(ESP_OK, s_region_err);

    teardown();
}

TEST_CASE("The region copy refuses a short buffer", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    char region[sizeof("us-east-1")];
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE,
                      esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region) - 1));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("us-east-1", region);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_get_region(s_h, NULL, 8));
    teardown();
}

TEST_CASE("An oversized credential response is refused, not truncated", "[aws_sign_http]")
{
    char *big = malloc(CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX + 2);
    TEST_ASSERT_NOT_NULL(big);
    memset(big, 'x', CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX + 1);
    big[CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX + 1] = '\0';

    /* Exactly the cap: the sink accepts it and the caller rejects the result. */
    install_http_port(big);
    s_http.cred_resp_len = CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);

    /* Past the cap, declared up front: the hint refuses the body. */
    install_http_port(big);
    s_http.cred_resp_len = CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX + 1;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);

    /* Past the cap, undeclared: the sink aborts the transfer mid-flight. */
    install_http_port(big);
    s_http.cred_resp_len = CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_RESPONSE_MAX + 1;
    s_http.chunked = true;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_NULL(s_creds.access_key_id);

    teardown();
    free(big);
}

TEST_CASE("An unsynchronised clock blocks all network I/O", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_synced = false;

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE,
                      esp_rmaker_aws_sign_creds_refresh(s_h, "alias", &s_creds));
    TEST_ASSERT_EQUAL(0, s_http.opens);

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL(0, s_http.opens);

    teardown();
}

/* Signed requests ************************************************************/

TEST_CASE("A signed GET carries the signature, date and session token", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{\"ok\":true}";
    s_http.resp_len = strlen(s_http.resp);

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));

    TEST_ASSERT_EQUAL_STRING("https://" API_HOST "/prod/v1/things", s_http.url);
    TEST_ASSERT_EQUAL(ESP_RMAKER_AWS_SIGN_HTTP_GET, s_http.method);
    TEST_ASSERT_TRUE(s_http.keep_alive);
    TEST_ASSERT_EQUAL_STRING(
        "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/execute-api/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, "
        "Signature=aa8d5f081cf8b50956eefaad8db847983e8ec9eef59149e0002c891f4ba90d5b",
        header_value("Authorization"));
    TEST_ASSERT_EQUAL_STRING("20150830T123600Z", header_value("x-amz-date"));
    TEST_ASSERT_EQUAL_STRING(EMPTY_PAYLOAD_HASH, header_value("x-amz-content-sha256"));
    TEST_ASSERT_EQUAL_STRING("TOK", header_value("x-amz-security-token"));
    TEST_ASSERT_EQUAL_STRING("AK", s_creds.access_key_id);     /* refreshed in place */

    TEST_ASSERT_EQUAL(200, resp.status_code);
    TEST_ASSERT_EQUAL(11, resp.body_len);
    TEST_ASSERT_EQUAL_STRING("{\"ok\":true}", (const char *)resp.body);
    esp_rmaker_aws_sign_response_free(&resp);

    teardown();
}

TEST_CASE("A signed POST signs its query, extra headers and body", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "";
    s_http.resp_len = 0;

    esp_rmaker_aws_sign_header_t extra[] = { { "content-type", "application/json" } };
    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    req.method = "POST";
    const esp_rmaker_aws_sign_query_param_t params[] = { { "b", "2" }, { "a", "1" } };
    req.params = params;
    req.params_count = 2;
    req.extra_headers = extra;
    req.extra_headers_count = 1;
    req.payload = (const uint8_t *)"{\"x\":1}";
    req.payload_len = 7;

    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));

    TEST_ASSERT_EQUAL_STRING("https://" API_HOST "/prod/v1/things?a=1&b=2", s_http.url);
    TEST_ASSERT_EQUAL(ESP_RMAKER_AWS_SIGN_HTTP_POST, s_http.method);
    TEST_ASSERT_EQUAL(7, s_http.body_len);
    TEST_ASSERT_EQUAL_STRING_LEN("{\"x\":1}", s_http.body, 7);
    TEST_ASSERT_EQUAL_STRING(
        "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/execute-api/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, "
        "Signature=338e0563b0242f4040f30b9fd7c239aa0c23fe2b9bfd65b1b8ece423313c8a8b",
        header_value("Authorization"));
    TEST_ASSERT_EQUAL_STRING(BODY_PAYLOAD_HASH, header_value("x-amz-content-sha256"));
    TEST_ASSERT_EQUAL_STRING("application/json", header_value("content-type"));

    TEST_ASSERT_EQUAL(0, resp.body_len);
    TEST_ASSERT_NULL(resp.body);
    esp_rmaker_aws_sign_response_free(&resp);

    teardown();
}

TEST_CASE("The connection is pooled per host", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    int after_first = s_http.opens;                 /* creds fetch + request connection */

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(after_first, s_http.opens);   /* reused, not reopened */
    TEST_ASSERT_EQUAL(1, s_http.set_urls);

    int closes = s_http.closes;
    req.host = OTHER_HOST;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(after_first + 1, s_http.opens);
    TEST_ASSERT_EQUAL(closes + 1, s_http.closes);   /* the old host was dropped first */
    TEST_ASSERT_EQUAL_STRING("https://" OTHER_HOST "/prod/v1/things", s_http.url);

    teardown();
}

TEST_CASE("A different timeout opens a new connection", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_HTTP_TIMEOUT_MS, s_http.timeout_ms);
    int opens = s_http.opens;

    req.timeout_ms = 1234;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(opens + 1, s_http.opens);
    TEST_ASSERT_EQUAL(1234, s_http.timeout_ms);

    /* The same timeout again reuses the new handle. */
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    TEST_ASSERT_EQUAL(opens + 1, s_http.opens);

    teardown();
}

TEST_CASE("A transport error drops the pooled connection", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    int opens = s_http.opens, closes = s_http.closes;

    s_http.perform_err = ESP_ERR_TIMEOUT;
    TEST_ASSERT_EQUAL(ESP_ERR_TIMEOUT, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_NULL(resp.body);
    TEST_ASSERT_EQUAL(0, resp.status_code);
    /* The pooled handle is retried once on a fresh connection, then both are dropped. */
    TEST_ASSERT_EQUAL(opens + 1, s_http.opens);
    TEST_ASSERT_EQUAL(closes + 2, s_http.closes);

    s_http.perform_err = ESP_OK;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL(opens + 2, s_http.opens);     /* had to reconnect */
    esp_rmaker_aws_sign_response_free(&resp);

    teardown();
}

TEST_CASE("A failure after the response started is not retried", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "";
    s_http.resp_len = 0;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    req.method = "POST";
    req.payload = (const uint8_t *)"{\"x\":1}";
    req.payload_len = 7;
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    esp_rmaker_aws_sign_response_free(&resp);
    int opens = s_http.opens, performs = s_http.performs;

    /* Headers of an empty-body reply arrived on the pooled handle, then the read failed. */
    s_http.fail_after_hint = true;
    TEST_ASSERT_EQUAL(ESP_FAIL, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL(performs + 1, s_http.performs);
    TEST_ASSERT_EQUAL(opens, s_http.opens);
    TEST_ASSERT_NULL(resp.body);

    teardown();
}

TEST_CASE("The path and query are percent-encoded once on the wire", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    const esp_rmaker_aws_sign_query_param_t params[] = { { "k", "a/b c" } };
    req.path = "/prod/v1/my file+1%.txt";
    req.params = params;
    req.params_count = 1;
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL_STRING("https://" API_HOST "/prod/v1/my%20file%2B1%25.txt?k=a%2Fb%20c", s_http.url);
    esp_rmaker_aws_sign_response_free(&resp);

    teardown();
}

TEST_CASE("A request region overrides the credential host's region", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{}";
    s_http.resp_len = 2;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    req.region = "eu-west-1";
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_EQUAL_STRING(
        "AWS4-HMAC-SHA256 Credential=AK/20150830/eu-west-1/execute-api/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, "
        "Signature=3f0b68c41cb2432f3b68a0bca2e331e7990c371073387ae8879d1f6446be7cb4",
        header_value("Authorization"));
    esp_rmaker_aws_sign_response_free(&resp);

    char region[ESP_RMAKER_AWS_SIGN_REGION_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(s_h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("us-east-1", region);

    teardown();
}

TEST_CASE("An oversized response is an error and frees the body", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    char *big = malloc(CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX + 1);
    TEST_ASSERT_NOT_NULL(big);
    memset(big, 'x', CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX + 1);
    s_http.resp = big;
    s_http.resp_len = CONFIG_ESP_RMAKER_AWS_SIGN_REQUEST_RESPONSE_MAX + 1;

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    TEST_ASSERT_NULL(resp.body);
    TEST_ASSERT_EQUAL(0, resp.body_len);

    teardown();
    free(big);
}

TEST_CASE("A bad request is rejected before any I/O", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    esp_rmaker_aws_sign_response_t resp = {0};
    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);

    req.method = "TRACE";
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));

#define ASSERT_REJECTED_WITHOUT(field) do {                                     \
        esp_rmaker_aws_sign_request_t broken = base_request(API_HOST);           \
        broken.field = NULL;                                                     \
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,                                   \
                          esp_rmaker_aws_sign_send_request(s_h, &broken, &resp)); \
    } while (0)

    ASSERT_REJECTED_WITHOUT(method);
    ASSERT_REJECTED_WITHOUT(host);
    ASSERT_REJECTED_WITHOUT(path);
    ASSERT_REJECTED_WITHOUT(service);
    ASSERT_REJECTED_WITHOUT(role_alias);
    ASSERT_REJECTED_WITHOUT(creds);
#undef ASSERT_REJECTED_WITHOUT

    /* A count with a NULL array; the payload makes the Content-Type scan run first. */
    req = base_request(API_HOST);
    req.payload = (const uint8_t *)"{}";
    req.payload_len = 2;
    req.extra_headers_count = 1;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    req = base_request(API_HOST);
    req.payload_len = 2;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    req = base_request(API_HOST);
    req.path = "prod/v1/things";
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
    req = base_request(API_HOST);

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, NULL, &resp));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, NULL));
    TEST_ASSERT_EQUAL(0, s_http.opens);

    teardown();
}

TEST_CASE("Repeated requests and their error paths leak nothing", "[aws_sign_http]")
{
    install_http_port(CREDS_JSON(CRED_EXPIRY));
    s_http.resp = "{\"ok\":true}";
    s_http.resp_len = strlen(s_http.resp);

    esp_rmaker_aws_sign_request_t req = base_request(API_HOST);
    esp_rmaker_aws_sign_response_t resp = {0};

    for (int round = 0; round < 4; round++) {
        if (round == 1) {
            test_aws_sign_heap_record();        /* after the first round warms every cache */
        }
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
        esp_rmaker_aws_sign_response_free(&resp);

        s_http.perform_err = ESP_ERR_TIMEOUT;
        TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
        s_http.perform_err = ESP_OK;

        req.method = "TRACE";
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_send_request(s_h, &req, &resp));
        req.method = "GET";
    }
    test_aws_sign_heap_check();

    teardown();
}

/* ESP port over loopback *****************************************************/

/* The host FreeRTOS port cannot preempt a task blocked in accept(), so this runs on chips only. */
#if !CONFIG_IDF_TARGET_LINUX

#define TOKEN_LEN       1400    /* AWS session tokens are 700-1500 bytes */
#define SERVER_TIMEOUT  2       /* seconds */
#define CLIENT_TIMEOUT  4000    /* ms */
#define BODY_LEN        8
#define RESPONSE        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

static struct {
    int listen_fd;
    TaskHandle_t waiter;
    char req[3072];
    size_t req_len;
    bool got_end;               /* the blank line that ends the request headers arrived */
} s_srv;

static char s_token[TOKEN_LEN + 1];

static void server_task(void *arg)
{
    (void)arg;
    int fd = accept(s_srv.listen_fd, NULL, NULL);
    if (fd >= 0) {
        struct timeval tv = { .tv_sec = SERVER_TIMEOUT };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while (!s_srv.got_end && s_srv.req_len < sizeof(s_srv.req) - 1) {
            int n = recv(fd, s_srv.req + s_srv.req_len, sizeof(s_srv.req) - 1 - s_srv.req_len, 0);
            if (n <= 0) {
                break;
            }
            s_srv.req_len += n;
            s_srv.req[s_srv.req_len] = '\0';
            s_srv.got_end = strstr(s_srv.req, "\r\n\r\n") != NULL;
        }
        if (s_srv.got_end) {
            send(fd, RESPONSE, strlen(RESPONSE), 0);
        }
        close(fd);
    }
    xTaskNotifyGive(s_srv.waiter);
    vTaskDelete(NULL);
}

/* Returns the port that the server listens on. */
static int server_start(void)
{
    memset(&s_srv, 0, sizeof(s_srv));
    s_srv.waiter = xTaskGetCurrentTaskHandle();
    esp_netif_init();
    esp_event_loop_create_default();    /* esp_http_client posts its events here */

    s_srv.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT_GREATER_OR_EQUAL(0, s_srv.listen_fd);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    TEST_ASSERT_EQUAL(0, bind(s_srv.listen_fd, (struct sockaddr *)&addr, sizeof(addr)));
    socklen_t addr_len = sizeof(addr);
    TEST_ASSERT_EQUAL(0, getsockname(s_srv.listen_fd, (struct sockaddr *)&addr, &addr_len));
    TEST_ASSERT_EQUAL(0, listen(s_srv.listen_fd, 1));
    struct timeval tv = { .tv_sec = SERVER_TIMEOUT };
    setsockopt(s_srv.listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(server_task, "loopback_srv", 4096, NULL, 5, NULL));
    return ntohs(addr.sin_port);
}

static void server_stop(void)
{
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS((SERVER_TIMEOUT + 2) * 1000));
    close(s_srv.listen_fd);
}

static int collect(void *ctx, const uint8_t *data, size_t len)
{
    char *body = ctx;
    size_t used = strlen(body);
    if (used + len >= BODY_LEN) {
        return 0;
    }
    memcpy(body + used, data, len);
    return (int)len;
}

TEST_CASE("A session token larger than the default TX buffer is sent in full", "[aws_sign_http]")
{
    for (int i = 0; i < TOKEN_LEN; i++) {
        s_token[i] = 'A' + i % 26;
    }
    s_token[TOKEN_LEN] = '\0';

    char url[48];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/t", server_start());
    const esp_rmaker_aws_sign_http_ops_t *ops = &esp_rmaker_aws_sign_esp_http_ops;
    const esp_rmaker_aws_sign_http_config_t cfg = {
        .url = url, .method = ESP_RMAKER_AWS_SIGN_HTTP_GET, .timeout_ms = CLIENT_TIMEOUT,
    };
    esp_rmaker_aws_sign_http_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, ops->open(&cfg, &h));
    TEST_ASSERT_EQUAL(ESP_OK, ops->set_header(h, "x-amz-security-token", s_token));

    char body[BODY_LEN] = {0};
    const esp_rmaker_aws_sign_http_receiver_t rx = { .sink = collect, .ctx = body };
    esp_err_t err = ops->perform(h, NULL, 0, &rx);
    int status = ops->status_code(h);
    ops->close(h);
    server_stop();

    TEST_ASSERT_TRUE_MESSAGE(s_srv.got_end, "the request headers never ended");
    TEST_ASSERT_NOT_NULL(strstr(s_srv.req, "x-amz-security-token: "));
    TEST_ASSERT_NOT_NULL(strstr(s_srv.req, s_token));
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(200, status);
    TEST_ASSERT_EQUAL_STRING("ok", body);
}
#endif /* !CONFIG_IDF_TARGET_LINUX */
