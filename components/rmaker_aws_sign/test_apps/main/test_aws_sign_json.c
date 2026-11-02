/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Conformance suite for the json port group, so a replacement backend can be held
 * to the same contract. Adversarial rather than happy-path: the input is a
 * network buffer that is not NUL-terminated. */

#include <string.h>
#include "unity.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"
#include "test_aws_sign.h"

static esp_err_t read_one(const char *doc, const char *object, const char *key,
                          char *buf, size_t cap, bool *found)
{
    esp_rmaker_aws_sign_json_field_t field = { .key = key, .buf = buf, .buf_size = cap };
    esp_err_t err = esp_rmaker_aws_sign_esp_json_ops.read_strs(doc, strlen(doc), object,
                                                               &field, 1);
    if (found) {
        *found = field.found;
    }
    return err;
}

TEST_CASE("Extracts values from an object and from the root", "[aws_sign_json]")
{
    char buf[64];
    bool found = false;

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"v\"}}", "c", "k", buf, sizeof(buf),
                                       &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("v", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"k\":\"root\"}", NULL, "k", buf, sizeof(buf), &found));
    TEST_ASSERT_EQUAL_STRING("root", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"\"}}", "c", "k", buf, sizeof(buf),
                                       &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{ \"c\" : { \"k\" : \"v\" } }", "c", "k", buf,
                                       sizeof(buf), &found));
    TEST_ASSERT_EQUAL_STRING("v", buf);
}

TEST_CASE("An absent key is reported, not an error", "[aws_sign_json]")
{
    char buf[64];
    bool found = true;
    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"x\":\"v\"}}", "c", "k", buf, sizeof(buf),
                                       &found));
    TEST_ASSERT_FALSE(found);
    TEST_ASSERT_EQUAL_STRING("", buf);
}

TEST_CASE("Escapes are unescaped, including surrogate pairs", "[aws_sign_json]")
{
    char buf[64];

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"a\\/b\"}}", "c", "k", buf, sizeof(buf),
                                       NULL));
    TEST_ASSERT_EQUAL_STRING("a/b", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"a\\\"\\\\b\"}}", "c", "k", buf,
                                       sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("a\"\\b", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"\\u0041\"}}", "c", "k", buf, sizeof(buf),
                                       NULL));
    TEST_ASSERT_EQUAL_STRING("A", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"\\u00e9\"}}", "c", "k", buf, sizeof(buf),
                                       NULL));
    TEST_ASSERT_EQUAL_STRING("\xc3\xa9", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"\\u20AC\"}}", "c", "k", buf, sizeof(buf),
                                       NULL));
    TEST_ASSERT_EQUAL_STRING("\xe2\x82\xac", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"\\uD83D\\uDE00\"}}", "c", "k", buf,
                                       sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("\xf0\x9f\x98\x80", buf);
}

/* A reader that searched for the key as text would fail all four of these. */
TEST_CASE("Keys are matched structurally, never as text", "[aws_sign_json]")
{
    char buf[64];

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"z\":\"x\\\"k\\\":\\\"EVIL\",\"k\":\"GOOD\"}}",
                                       "c", "k", buf, sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("GOOD", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"o\":{\"k\":\"D\"},\"c\":{\"k\":\"GOOD\"}}", "c", "k",
                                       buf, sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("GOOD", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"k\":\"D\",\"c\":{\"k\":\"GOOD\"}}", "c", "k", buf,
                                       sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("GOOD", buf);

    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"o\":{\"k\":\"DEEP\"},\"k\":\"GOOD\"}}", "c",
                                       "k", buf, sizeof(buf), NULL));
    TEST_ASSERT_EQUAL_STRING("GOOD", buf);
}

TEST_CASE("Malformed and ambiguous documents are rejected", "[aws_sign_json]")
{
    static const char *rejected[] = {
        "{\"c\":{\"k\":\"v\",\"k\":\"w\"}}",     /* duplicate requested key */
        "{\"c\":{\"k\":5}}",                     /* value is not a string */
        "{\"c\":{\"k\":\"unterminated",          /* truncated mid-string */
        "{\"c\":{\"k\":\"v\"",                   /* truncated mid-object */
        "",                                      /* empty input */
        "[1,2]",                                 /* root is not an object */
        "{\"c\":5}",                             /* target is not an object */
        "{\"c\":{\"k\" \"v\"}}",                 /* missing colon */
        "{\"c\":{\"k\":\"a\tb\"}}",              /* raw control character */
        "{\"c\":{\"k\":\"\\uD83D\"}}",           /* lone high surrogate */
        "{\"c\":{\"k\":\"\\uDE00\"}}",           /* lone low surrogate */
        "{\"c\":{\"k\":\"\\uZZZZ\"}}",           /* bad hex */
        "{\"c\":{\"k\":\"\\u12\"}}",             /* truncated \uXXXX */
        "{\"c\":{\"k\":\"\\u0000\"}}",           /* NUL cannot survive in the value */
    };
    char buf[64];
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        esp_rmaker_aws_sign_json_field_t field = { .key = "k", .buf = buf, .buf_size = sizeof(buf) };
        esp_err_t err = esp_rmaker_aws_sign_esp_json_ops.read_strs(rejected[i],
                                                                   strlen(rejected[i]), "c",
                                                                   &field, 1);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(ESP_OK, err, rejected[i]);
        TEST_ASSERT_FALSE(field.found);
        TEST_ASSERT_EQUAL(0, field.len);
        TEST_ASSERT_EQUAL_STRING("", buf);
    }
}

TEST_CASE("A value too long for its buffer is an error", "[aws_sign_json]")
{
    char small[4];
    TEST_ASSERT_NOT_EQUAL(ESP_OK, read_one("{\"c\":{\"k\":\"abcdef\"}}", "c", "k", small,
                                           sizeof(small), NULL));
}

TEST_CASE("A duplicate of an unrequested key is ignored", "[aws_sign_json]")
{
    char buf[64];
    bool found = false;
    TEST_ASSERT_EQUAL(ESP_OK, read_one("{\"c\":{\"x\":\"1\",\"x\":\"2\",\"k\":\"v\"}}", "c", "k",
                                       buf, sizeof(buf), &found));
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("v", buf);
}

TEST_CASE("A batch distinguishes present from absent, and fails closed", "[aws_sign_json]")
{
    char first[16], second[16];

    esp_rmaker_aws_sign_json_field_t partial[2] = {
        { .key = "a", .buf = first, .buf_size = sizeof(first) },
        { .key = "zz", .buf = second, .buf_size = sizeof(second) },
    };
    const char *doc = "{\"c\":{\"a\":\"ok\"}}";
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_esp_json_ops.read_strs(doc, strlen(doc), "c",
                                                                         partial, 2));
    TEST_ASSERT_TRUE(partial[0].found);
    TEST_ASSERT_FALSE(partial[1].found);
    TEST_ASSERT_EQUAL_STRING("ok", first);

    /* The first field parses and the second then fails: both must be cleared. */
    esp_rmaker_aws_sign_json_field_t batch[2] = {
        { .key = "a", .buf = first, .buf_size = sizeof(first) },
        { .key = "b", .buf = second, .buf_size = sizeof(second) },
    };
    const char *bad = "{\"c\":{\"a\":\"ok\",\"b\":7}}";
    TEST_ASSERT_NOT_EQUAL(ESP_OK, esp_rmaker_aws_sign_esp_json_ops.read_strs(bad, strlen(bad),
                                                                             "c", batch, 2));
    TEST_ASSERT_FALSE(batch[0].found);
    TEST_ASSERT_FALSE(batch[1].found);
    TEST_ASSERT_EQUAL_STRING("", first);
}

TEST_CASE("Only len bytes are read, never up to a NUL", "[aws_sign_json]")
{
    static const char doc[] = { '{', '"', 'k', '"', ':', '"', 'v', '"', '}', 'X', 'X' };
    char buf[16];
    esp_rmaker_aws_sign_json_field_t field = { .key = "k", .buf = buf, .buf_size = sizeof(buf) };
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_esp_json_ops.read_strs(doc, 9, NULL,
                                                                         &field, 1));
    TEST_ASSERT_EQUAL_STRING("v", buf);
}
