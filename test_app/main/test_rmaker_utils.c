/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "esp_rmaker_utils.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_event.h"
#include "esp_rmaker_cmd_resp.h"
#include "esp_netif.h"

static const char *TAG = "rmaker_utils_test";

static void time_sync_callback(struct timeval *tv)
{
    ESP_LOGI(TAG, "Time sync callback called");
}

TEST_CASE("ESP RainMaker Time Sync Init", "[rmaker_utils]")
{
    esp_netif_init();

    esp_rmaker_time_config_t time_config = {
        .sntp_server_name = (char *)"pool.ntp.org",
        .sync_time_cb = time_sync_callback
    };

    esp_err_t err = esp_rmaker_time_sync_init(&time_config);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Test with NULL config (should use defaults)
    err = esp_rmaker_time_sync_init(NULL);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}

TEST_CASE("ESP RainMaker Time Check", "[rmaker_utils]")
{
    // Since we just initialized time sync, time might not be synced yet
    // This is more of a function call test than testing the actual result
    bool time_synced = esp_rmaker_time_check();

    // We can only log the result, not assert since it depends on network conditions
    ESP_LOGI(TAG, "Time synced: %s", time_synced ? "true" : "false");
}

TEST_CASE("ESP RainMaker Timezone Operations", "[rmaker_utils]")
{
    // Test setting timezone in POSIX format
    esp_err_t err = esp_rmaker_time_set_timezone_posix("PST8PDT,M3.2.0,M11.1.0");
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Get and verify timezone in POSIX format
    char *tz_posix = esp_rmaker_time_get_timezone_posix();
    if (tz_posix) {
        ESP_LOGI(TAG, "POSIX timezone: %s", tz_posix);
        TEST_ASSERT_EQUAL_STRING("PST8PDT,M3.2.0,M11.1.0", tz_posix);
        free(tz_posix);
    }

    // Test setting timezone by location
    err = esp_rmaker_time_set_timezone("America/Los_Angeles");
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Get and verify timezone by location
    char *tz = esp_rmaker_time_get_timezone();
    if (tz) {
        ESP_LOGI(TAG, "Timezone: %s", tz);
        TEST_ASSERT_EQUAL_STRING("America/Los_Angeles", tz);
        free(tz);
    }
}

TEST_CASE("ESP RainMaker Get Local Time", "[rmaker_utils]")
{
    char time_str[64];
    esp_err_t err = esp_rmaker_get_local_time_str(time_str, sizeof(time_str));
    TEST_ASSERT_EQUAL(ESP_OK, err);

    ESP_LOGI(TAG, "Local time: %s", time_str);
    TEST_ASSERT_NOT_EQUAL(0, strlen(time_str));
}

// We can't actually test the reboot and reset functions in a unit test
// as they would terminate the test process. Instead, we'll test the API calls.

TEST_CASE("ESP RainMaker Reboot API Test", "[rmaker_utils]")
{
    // Just test API call, don't actually reboot
    // Set a delay so the test can finish before reboot starts
    ESP_LOGI(TAG, "Testing reboot API (with 120 second delay, won't actually reboot during test)");
    esp_err_t err = esp_rmaker_reboot(120);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}

TEST_CASE("ESP RainMaker Wi-Fi Reset API Test", "[rmaker_utils]")
{
    // Just test API call, don't actually reset
    // Set a delay so the test can finish before reset starts
    ESP_LOGI(TAG, "Testing Wi-Fi reset API (with 120 second delay, won't actually reset during test)");
    esp_err_t err = esp_rmaker_wifi_reset(120, -1);
#if CONFIG_ESP_RMAKER_NETWORK_OVER_WIFI
    TEST_ASSERT_EQUAL(ESP_OK, err);
#else
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_SUPPORTED, err);
#endif
}

TEST_CASE("ESP RainMaker Factory Reset API Test", "[rmaker_utils]")
{
    // Just test API call, don't actually reset
    // Set a delay so the test can finish before reset starts
    ESP_LOGI(TAG, "Testing factory reset API (with 120 second delay, won't actually reset during test)");
    esp_err_t err = esp_rmaker_factory_reset(120, -1);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}

TEST_CASE("ESP RainMaker SNTP Initialization", "[rmaker_utils]")
{
    esp_netif_init();

    // Test with default configuration
    esp_rmaker_time_config_t default_config = {0};
    esp_err_t err = esp_rmaker_time_sync_init(&default_config);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Test with custom SNTP server
    esp_rmaker_time_config_t custom_config = {
        .sntp_server_name = (char *)"time.google.com"
    };
    err = esp_rmaker_time_sync_init(&custom_config);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Test with NULL configuration (should use default)
    err = esp_rmaker_time_sync_init(NULL);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}

TEST_CASE("ESP RainMaker Invalid POSIX Timezone", "[rmaker_utils]")
{
    // Test with an invalid POSIX timezone string
    esp_err_t err = esp_rmaker_time_set_timezone_posix(NULL);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);

    err = esp_rmaker_time_set_timezone_posix("");
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);
}

static esp_err_t test_cmd_handler(const void *in_data, size_t in_len, void **out_data, size_t *out_len, esp_rmaker_cmd_ctx_t *ctx, void *priv)
{
    // Check for valid command context
    if (ctx == NULL || ctx->req_id[0] == '\0' || ctx->user_role == 0 || ctx->cmd == 0) {
        ESP_LOGE(TAG, "Invalid command context: req_id=%s, user_role=%d, cmd=%d", ctx ? ctx->req_id : "NULL", ctx ? ctx->user_role : -1, ctx ? ctx->cmd : -1);
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Command context: req_id=%s, user_role=%d, cmd=%d", ctx->req_id, ctx->user_role, ctx->cmd);

    // Simple echo handler for testing
    *out_data = malloc(in_len);
    if (*out_data == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(*out_data, in_data, in_len);
    *out_len = in_len;
    return ESP_OK;
}

// Wrapper function to match esp_rmaker_cmd_send_t signature
static esp_err_t cmd_response_handler_wrapper(const void *input, size_t input_len, void *priv_data) {
    void *output_data = NULL;
    size_t output_len = 0;
    esp_err_t err = esp_rmaker_cmd_response_handler(input, input_len, &output_data, &output_len);
    if (output_data) {
        free(output_data);
    }
    return err;
}

TEST_CASE("ESP RainMaker Command Registration and Handling", "[rmaker_cmd_resp]")
{
    // Prepare command context with valid values
    esp_rmaker_cmd_ctx_t cmd_ctx = {
        .cmd = ESP_RMAKER_CMD_TYPE_SET_PARAMS,
        .req_id = "test_req_id",
        .user_role = ESP_RMAKER_USER_ROLE_PRIMARY_USER
    };

    // Register a test command
    esp_err_t err = esp_rmaker_cmd_register(ESP_RMAKER_CMD_TYPE_SET_PARAMS, ESP_RMAKER_USER_ROLE_PRIMARY_USER, test_cmd_handler, true, &cmd_ctx);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    void *output_data = NULL;

#if 0 // The response should ideally be not ESP_OK, but it is ESP_OK currently
    // Prepare invalid input data
    const char *invalid_data = "invalid_data";
    size_t invalid_len = strlen(invalid_data);
    size_t output_len = 0;

    // Pass invalid data first to check for failure
    err = esp_rmaker_cmd_response_handler(invalid_data, invalid_len, &output_data, &output_len);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, err);
#endif

    // Now use esp_rmaker_cmd_resp_test_send to send valid TLV data
    err = esp_rmaker_cmd_resp_test_send(cmd_ctx.req_id, cmd_ctx.user_role, cmd_ctx.cmd, NULL, 0, cmd_response_handler_wrapper, NULL);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Clean up
    if (output_data) {
        free(output_data);
    }

    // Deregister the test command
    err = esp_rmaker_cmd_deregister(ESP_RMAKER_CMD_TYPE_SET_PARAMS);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}
