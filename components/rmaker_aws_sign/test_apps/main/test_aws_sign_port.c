/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Port validation: a partially filled table must be refused at install time
 * rather than fail at some unpredictable later point. */

#include <string.h>
#include "unity.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"
#include "esp_rmaker_aws_sign_internal.h"
#include "test_aws_sign.h"

static esp_rmaker_aws_sign_mutex_t stub_mutex_create(void)
{
    return (esp_rmaker_aws_sign_mutex_t)1;
}

static esp_err_t stub_http_open(const esp_rmaker_aws_sign_http_config_t *cfg,
                                esp_rmaker_aws_sign_http_handle_t *out)
{
    (void)cfg;
    (void)out;
    return ESP_FAIL;
}

static esp_rmaker_aws_sign_port_config_t signer_port(void)
{
    esp_rmaker_aws_sign_port_config_t port = {
        .mem = esp_rmaker_aws_sign_esp_mem_ops,
        .crypto = esp_rmaker_aws_sign_esp_crypto_ops,
        .time = esp_rmaker_aws_sign_esp_time_ops,
        .json = esp_rmaker_aws_sign_esp_json_ops,
        .log = esp_rmaker_aws_sign_esp_log,
    };
    return port;
}

TEST_CASE("A port missing a required member is refused", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(NULL));

    esp_rmaker_aws_sign_port_config_t port = signer_port();
    port.mem.calloc = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port = signer_port();
    port.crypto.sha256_update = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port = signer_port();
    port.crypto.hmac_sha256 = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port = signer_port();
    port.time.get_time = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));
    TEST_ASSERT_FALSE(esp_rmaker_aws_sign_port_is_installed());
}

TEST_CASE("Optional groups are all-or-nothing", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();

    esp_rmaker_aws_sign_port_config_t port = signer_port();
    port.mutex.create = stub_mutex_create;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port = signer_port();
    port.http.open = stub_http_open;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    /* A complete HTTP table still needs mutex and json to serve it. */
    port = signer_port();
    port.http = esp_rmaker_aws_sign_esp_http_ops;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port.mutex = esp_rmaker_aws_sign_esp_mutex_ops;
    port.json.read_strs = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_port_install(&port));

    port.json = esp_rmaker_aws_sign_esp_json_ops;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
    esp_rmaker_aws_sign_port_uninstall();
}

TEST_CASE("Re-installing the same port is a no-op, a different one is not", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();

    esp_rmaker_aws_sign_port_config_t port = signer_port();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
    TEST_ASSERT_TRUE(esp_rmaker_aws_sign_port_is_installed());

    esp_rmaker_aws_sign_port_config_t other = port;
    other.log = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_aws_sign_port_install(&other));
    esp_rmaker_aws_sign_port_uninstall();
}

static esp_rmaker_aws_sign_port_config_t s_nested_port;
static esp_err_t s_nested_err;
static bool s_nested_installed;

/* Runs inside the outer install, where a second task's install would overlap it. */
static esp_err_t nested_install_init(void)
{
    s_nested_err = esp_rmaker_aws_sign_port_install(&s_nested_port);
    s_nested_installed = esp_rmaker_aws_sign_port_is_installed();
    return ESP_OK;
}

static esp_err_t failing_init(void)
{
    return ESP_FAIL;
}

TEST_CASE("An install in progress refuses another install", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    s_nested_port = signer_port();
    s_nested_port.crypto.init = nested_install_init;
    s_nested_err = ESP_OK;
    s_nested_installed = true;

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&s_nested_port));
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FINISHED, s_nested_err);
    TEST_ASSERT_FALSE(s_nested_installed);
    TEST_ASSERT_TRUE(esp_rmaker_aws_sign_port_is_installed());
    esp_rmaker_aws_sign_port_uninstall();
}

TEST_CASE("A failed install leaves no port behind", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    esp_rmaker_aws_sign_port_config_t port = signer_port();
    port.crypto.init = failing_init;
    TEST_ASSERT_EQUAL(ESP_FAIL, esp_rmaker_aws_sign_port_install(&port));
    TEST_ASSERT_FALSE(esp_rmaker_aws_sign_port_is_installed());

    port = signer_port();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install(&port));
    esp_rmaker_aws_sign_port_uninstall();
}

TEST_CASE("The default port installs once and keeps its identity", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install_default());
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install_default());

    /* A second user that only signs can rely on the port already installed. */
    TEST_ASSERT_TRUE(esp_rmaker_aws_sign_port_is_installed());
    esp_rmaker_aws_sign_port_config_t signer = signer_port();
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_aws_sign_port_install(&signer));
    esp_rmaker_aws_sign_port_uninstall();
}

static const esp_rmaker_aws_sign_config_t s_good_config = {
    .cred_host = "c1abcdef.credentials.iot.ap-south-1.amazonaws.com",
    .thing_name = "node1234",
    .client_cert = "-----BEGIN CERTIFICATE-----\n",
    .client_key = "-----BEGIN PRIVATE KEY-----\n",
};

TEST_CASE("Create needs a port with http ops", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    esp_rmaker_aws_sign_handle_t h = (esp_rmaker_aws_sign_handle_t)1;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_aws_sign_create(&s_good_config, &h));
    TEST_ASSERT_NULL(h);

    test_aws_sign_install_signer_port();
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_SUPPORTED, esp_rmaker_aws_sign_create(&s_good_config, &h));
    TEST_ASSERT_NULL(h);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_create(&s_good_config, NULL));
}

TEST_CASE("The config is validated and the region derived from it", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install_default());
    esp_rmaker_aws_sign_handle_t h = NULL;

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_create(NULL, &h));

    esp_rmaker_aws_sign_config_t missing_key = s_good_config;
    missing_key.client_key = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_create(&missing_key, &h));
    TEST_ASSERT_NULL(h);

    esp_rmaker_aws_sign_config_t no_region = s_good_config;
    no_region.cred_host = "credentials.example.com";
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_create(&no_region, &h));
    TEST_ASSERT_NULL(h);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_create(&s_good_config, &h));
    char region[16];
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_get_region(h, region, sizeof(region)));
    TEST_ASSERT_EQUAL_STRING("ap-south-1", region);
    esp_rmaker_aws_sign_destroy(h);
    esp_rmaker_aws_sign_port_uninstall();
}

TEST_CASE("Calls without a live handle are refused", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_port_install_default());

    struct esp_rmaker_aws_sign_ctx fake = {0};
    esp_rmaker_aws_sign_handle_t bad[] = { NULL, &fake };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char region[16];
        esp_rmaker_aws_sign_creds_t creds = {0};
        esp_rmaker_aws_sign_request_t req = {
            .method = "GET", .host = "api.execute-api.us-east-1.amazonaws.com", .path = "/",
            .service = "execute-api", .role_alias = "alias", .creds = &creds,
        };
        esp_rmaker_aws_sign_response_t resp = {0};
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_get_region(bad[i], region, 16));
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                          esp_rmaker_aws_sign_set_cred_host(bad[i], "h", "us-east-1"));
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                          esp_rmaker_aws_sign_creds_refresh(bad[i], "alias", &creds));
        TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                          esp_rmaker_aws_sign_send_request(bad[i], &req, &resp));
        TEST_ASSERT_NULL(creds.access_key_id);
        esp_rmaker_aws_sign_destroy(bad[i]);     /* a no-op */
    }
    esp_rmaker_aws_sign_port_uninstall();
}

TEST_CASE("Nothing signs before a port is installed", "[aws_sign_port]")
{
    esp_rmaker_aws_sign_port_uninstall();
    esp_rmaker_aws_sign_sigv4_input_t in = {
        .method = "GET", .host = "example.amazonaws.com", .path = "/",
        .access_key_id = "AKIDEXAMPLE", .secret_access_key = "secret",
        .region = "us-east-1", .service = "service", .now_epoch_sec = 1440938160,
    };
    esp_rmaker_aws_sign_sigv4_output_t out = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_aws_sign_sigv4(&in, &out));

    test_aws_sign_install_signer_port();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_sigv4(&in, &out));
    esp_rmaker_aws_sign_sigv4_output_free(&out);
}
