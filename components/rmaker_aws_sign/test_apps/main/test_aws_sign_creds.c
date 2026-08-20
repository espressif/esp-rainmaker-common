/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* The pure parts of the credentials layer: region parsing, the ISO8601 expiry and
 * the response parse. No clock, no IO, no mocks. */

#include <string.h>
#include "unity.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_internal.h"
#include "test_aws_sign.h"

#define GOOD_RESPONSE \
    "{\"credentials\":{\"accessKeyId\":\"AK\",\"secretAccessKey\":\"SK\"," \
    "\"sessionToken\":\"TOK\",\"expiration\":\"2026-06-11T08:31:00Z\"}}"

TEST_CASE("Region is parsed from a credential-provider host", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    static const struct {
        const char *host;
        const char *region;
    } cases[] = {
        { "abc.credentials.iot.us-east-1.amazonaws.com", "us-east-1" },
        { "abc.credentials.iot.ap-south-1.amazonaws.com", "ap-south-1" },
        { "api.execute-api.eu-west-1.amazonaws.com", "eu-west-1" },
        { "bkt.s3.us-east-1.amazonaws.com", "us-east-1" },
        { "s3.us-gov-west-1.amazonaws.com", "us-gov-west-1" },
        { "iot.cn-north-1.amazonaws.com.cn", "cn-north-1" },
        { "kinesisvideo.us-west-2.amazonaws.com", "us-west-2" },
        { "example.com", NULL },
        { ".amazonaws.com", NULL },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *region = esp_rmaker_aws_sign_parse_region_from_host(cases[i].host);
        if (cases[i].region == NULL) {
            TEST_ASSERT_NULL_MESSAGE(region, cases[i].host);
        } else {
            TEST_ASSERT_NOT_NULL_MESSAGE(region, cases[i].host);
            TEST_ASSERT_EQUAL_STRING(cases[i].region, region);
        }
        esp_rmaker_aws_sign_free(region);
    }
    TEST_ASSERT_NULL(esp_rmaker_aws_sign_parse_region_from_host(NULL));
}

TEST_CASE("ISO8601 expiry parses, and malformed input yields 0", "[aws_sign_creds]")
{
    TEST_ASSERT_EQUAL_I64(1440938160, esp_rmaker_aws_sign_iso8601_to_epoch("2015-08-30T12:36:00Z"));
    TEST_ASSERT_EQUAL_I64(0, esp_rmaker_aws_sign_iso8601_to_epoch("1970-01-01T00:00:00Z"));
    TEST_ASSERT_EQUAL_I64(1781166660, esp_rmaker_aws_sign_iso8601_to_epoch("2026-06-11T08:31:00Z"));
    TEST_ASSERT_EQUAL_I64(0, esp_rmaker_aws_sign_iso8601_to_epoch("2026-06-11 08:31:00"));
    TEST_ASSERT_EQUAL_I64(0, esp_rmaker_aws_sign_iso8601_to_epoch("garbage"));
    TEST_ASSERT_EQUAL_I64(0, esp_rmaker_aws_sign_iso8601_to_epoch(""));
    TEST_ASSERT_EQUAL_I64(0, esp_rmaker_aws_sign_iso8601_to_epoch(NULL));
}

TEST_CASE("A credential response parses into owned strings", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    esp_rmaker_aws_sign_creds_t creds = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_parse_creds_json(GOOD_RESPONSE,
                                                                   strlen(GOOD_RESPONSE), &creds));
    TEST_ASSERT_EQUAL_STRING("AK", creds.access_key_id);
    TEST_ASSERT_EQUAL_STRING("SK", creds.secret_access_key);
    TEST_ASSERT_EQUAL_STRING("TOK", creds.session_token);
    TEST_ASSERT_EQUAL_I64(1781166660, creds.expiration_epoch_sec);
    esp_rmaker_aws_sign_creds_free(&creds);
    TEST_ASSERT_NULL(creds.access_key_id);
}

TEST_CASE("A missing expiration leaves the fallback to the caller", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    const char *no_expiry = "{\"credentials\":{\"accessKeyId\":\"AK\","
                            "\"secretAccessKey\":\"SK\",\"sessionToken\":\"TOK\"}}";
    esp_rmaker_aws_sign_creds_t creds = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_parse_creds_json(no_expiry, strlen(no_expiry),
                                                                   &creds));
    TEST_ASSERT_EQUAL_I64(0, creds.expiration_epoch_sec);
    esp_rmaker_aws_sign_creds_free(&creds);

    const char *bad_expiry = "{\"credentials\":{\"accessKeyId\":\"AK\","
                             "\"secretAccessKey\":\"SK\",\"sessionToken\":\"TOK\","
                             "\"expiration\":\"nonsense\"}}";
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_parse_creds_json(bad_expiry, strlen(bad_expiry),
                                                                   &creds));
    TEST_ASSERT_EQUAL_I64(0, creds.expiration_epoch_sec);
    esp_rmaker_aws_sign_creds_free(&creds);
}

TEST_CASE("A malformed credential response allocates nothing", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    static const char *rejected[] = {
        "{\"credentials\":{\"accessKeyId\":\"AK\"}}",           /* missing mandatory fields */
        "{\"nope\":{\"accessKeyId\":\"AK\"}}",                  /* no credentials object */
        "{\"credentials\":5}",                                  /* credentials is not an object */
        "{\"credentials\":{\"accessKeyId\":\"AK\"",             /* truncated */
    };
    esp_rmaker_aws_sign_creds_t creds = {0};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        TEST_ASSERT_NOT_EQUAL_MESSAGE(ESP_OK,
                                      esp_rmaker_aws_sign_parse_creds_json(rejected[i],
                                                                           strlen(rejected[i]),
                                                                           &creds),
                                      rejected[i]);
        TEST_ASSERT_NULL(creds.access_key_id);
        TEST_ASSERT_NULL(creds.secret_access_key);
        TEST_ASSERT_NULL(creds.session_token);
    }
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_parse_creds_json(NULL, 0, &creds));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_aws_sign_parse_creds_json(GOOD_RESPONSE,
                                                                                strlen(GOOD_RESPONSE),
                                                                                NULL));
}

/* A key name hidden inside a string value must not be mistaken for a real key. */
TEST_CASE("A hostile credential response cannot smuggle a key", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    const char *evil = "{\"credentials\":{\"sessionToken\":\"x\\\"accessKeyId\\\":\\\"EVIL\","
                       "\"accessKeyId\":\"GOOD\",\"secretAccessKey\":\"SK\"}}";
    esp_rmaker_aws_sign_creds_t creds = {0};
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_parse_creds_json(evil, strlen(evil), &creds));
    TEST_ASSERT_EQUAL_STRING("GOOD", creds.access_key_id);
    esp_rmaker_aws_sign_creds_free(&creds);
}

TEST_CASE("Without http ops the network layers are unavailable", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    const esp_rmaker_aws_sign_config_t config = {
        .cred_host = "c1abcdef.credentials.iot.us-east-1.amazonaws.com",
        .thing_name = "node1234",
        .client_cert = "-----BEGIN CERTIFICATE-----\n",
        .client_key = "-----BEGIN PRIVATE KEY-----\n",
    };
    esp_rmaker_aws_sign_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_SUPPORTED, esp_rmaker_aws_sign_create(&config, &h));
    TEST_ASSERT_NULL(h);
}

TEST_CASE("Credential parsing leaks nothing on any path", "[aws_sign_creds]")
{
    test_aws_sign_install_signer_port();
    static const char *inputs[] = {
        GOOD_RESPONSE,
        "{\"credentials\":{\"accessKeyId\":\"AK\"}}",
        "{\"nope\":{\"accessKeyId\":\"AK\"}}",
        "{\"credentials\":5}",
        "{\"credentials\":{\"accessKeyId\":\"AK\"",
    };
    for (int round = 0; round < 4; round++) {
        if (round == 1) {
            test_aws_sign_heap_record();    /* after one warm-up round */
        }
        for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
            esp_rmaker_aws_sign_creds_t creds = {0};
            esp_rmaker_aws_sign_parse_creds_json(inputs[i], strlen(inputs[i]), &creds);
            esp_rmaker_aws_sign_creds_free(&creds);
        }
        char *region = esp_rmaker_aws_sign_parse_region_from_host("bkt.s3.eu-west-1.amazonaws.com");
        TEST_ASSERT_NOT_NULL(region);
        esp_rmaker_aws_sign_free(region);
    }
    test_aws_sign_heap_check();
}
