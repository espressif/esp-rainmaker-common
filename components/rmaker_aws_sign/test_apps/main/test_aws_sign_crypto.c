/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Known-answer vectors for the crypto port: FIPS 180-4 for SHA-256 and RFC 4231
 * for HMAC, so they validate a backend against the standard rather than against
 * this component. Run these before trusting any other AWS signing test. */

#include <string.h>
#include "unity.h"
#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"
#include "test_aws_sign.h"

#define EMPTY_DIGEST "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define ABC_DIGEST   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define LONG_DIGEST  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

static const char LONG_MSG[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/* Runs init first, as port install does. */
static const esp_rmaker_aws_sign_crypto_ops_t *crypto(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_aws_sign_esp_crypto_ops.init());
    return &esp_rmaker_aws_sign_esp_crypto_ops;
}

static void digest_of_chunks(const char *chunks[], int count, uint8_t out[32])
{
    esp_rmaker_aws_sign_sha256_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_init(&ctx));
    for (int i = 0; i < count; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_update(&ctx, (const uint8_t *)chunks[i],
                                                          strlen(chunks[i])));
    }
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_finish(&ctx, out));
}

TEST_CASE("SHA-256 of the empty message", "[aws_sign_crypto]")
{
    uint8_t digest[32];
    digest_of_chunks(NULL, 0, digest);
    test_aws_sign_assert_digest(EMPTY_DIGEST, digest);

    const char *empties[] = { "", "", "" };
    digest_of_chunks(empties, 3, digest);
    test_aws_sign_assert_digest(EMPTY_DIGEST, digest);
}

TEST_CASE("SHA-256 is independent of the chunking", "[aws_sign_crypto]")
{
    uint8_t digest[32];
    const char *one[] = { "abc" };
    const char *three[] = { "a", "b", "c" };
    const char *with_gap[] = { "ab", "", "c" };

    digest_of_chunks(one, 1, digest);
    test_aws_sign_assert_digest(ABC_DIGEST, digest);
    digest_of_chunks(three, 3, digest);
    test_aws_sign_assert_digest(ABC_DIGEST, digest);
    digest_of_chunks(with_gap, 3, digest);
    test_aws_sign_assert_digest(ABC_DIGEST, digest);
}

TEST_CASE("SHA-256 straddling the block boundary, one byte at a time", "[aws_sign_crypto]")
{
    uint8_t digest[32];
    const char *whole[] = { LONG_MSG };
    digest_of_chunks(whole, 1, digest);
    test_aws_sign_assert_digest(LONG_DIGEST, digest);

    esp_rmaker_aws_sign_sha256_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_init(&ctx));
    for (size_t i = 0; i < strlen(LONG_MSG); i++) {
        TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_update(&ctx, (const uint8_t *)&LONG_MSG[i], 1));
    }
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_finish(&ctx, digest));
    test_aws_sign_assert_digest(LONG_DIGEST, digest);
}

TEST_CASE("sha256_abort tolerates an uninitialised context", "[aws_sign_crypto]")
{
    esp_rmaker_aws_sign_sha256_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    crypto()->sha256_abort(&ctx);

    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_init(&ctx));
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->sha256_update(&ctx, (const uint8_t *)"abc", 3));
    crypto()->sha256_abort(&ctx);
}

TEST_CASE("HMAC-SHA-256 matches RFC 4231", "[aws_sign_crypto]")
{
    uint8_t key[131], msg[50], mac[32];

    memset(key, 0x0b, 20);
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, mac));
    test_aws_sign_assert_digest("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                                mac);

    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256((const uint8_t *)"Jefe", 4,
                                                    (const uint8_t *)"what do ya want for nothing?",
                                                    28, mac));
    test_aws_sign_assert_digest("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                                mac);

    memset(key, 0xaa, 20);
    memset(msg, 0xdd, 50);
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, 20, msg, 50, mac));
    test_aws_sign_assert_digest("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                                mac);

    for (int i = 0; i < 25; i++) {
        key[i] = (uint8_t)(i + 1);
    }
    memset(msg, 0xcd, 50);
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, 25, msg, 50, mac));
    test_aws_sign_assert_digest("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                                mac);
}

/* The long-key path is dead code in production - every key this component uses is
 * under the 64-byte block - which is exactly why a port must be tested on it. */
TEST_CASE("HMAC-SHA-256 hashes a key longer than the block", "[aws_sign_crypto]")
{
    uint8_t key[131], mac[32];
    memset(key, 0xaa, sizeof(key));

    const char *tc6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, sizeof(key), (const uint8_t *)tc6,
                                                    strlen(tc6), mac));
    test_aws_sign_assert_digest("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                                mac);

    const char *tc7 = "This is a test using a larger than block-size key and a larger than "
                      "block-size data. The key needs to be hashed before being used by the "
                      "HMAC algorithm.";
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, sizeof(key), (const uint8_t *)tc7,
                                                    strlen(tc7), mac));
    test_aws_sign_assert_digest("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                                mac);
}

/* 64 vs 65 pins the key_len > BLOCK branch boundary, an off-by-one waiting to happen. */
TEST_CASE("HMAC-SHA-256 edge cases around the key length", "[aws_sign_crypto]")
{
    uint8_t key[65], mac[32];

    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256((const uint8_t *)"", 0,
                                                    (const uint8_t *)"abc", 3, mac));
    test_aws_sign_assert_digest("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351",
                                mac);

    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256((const uint8_t *)"key", 3,
                                                    (const uint8_t *)"", 0, mac));
    test_aws_sign_assert_digest("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0",
                                mac);

    memset(key, 0x5a, sizeof(key));
    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, 64, (const uint8_t *)"abc", 3, mac));
    test_aws_sign_assert_digest("e88b2a6b8773b3d1b92adb63b49cfb24d959afcb06a9166985967499f6755df8",
                                mac);

    TEST_ASSERT_EQUAL(ESP_OK, crypto()->hmac_sha256(key, 65, (const uint8_t *)"abc", 3, mac));
    test_aws_sign_assert_digest("62761f7ca1413e134d54bc71b41b4d4af91c5b4d2c9cb408025d349a60b6697f",
                                mac);
}
