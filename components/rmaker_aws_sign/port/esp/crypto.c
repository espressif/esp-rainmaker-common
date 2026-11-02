/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file crypto.c
 * @brief PSA Crypto implementation of esp_rmaker_aws_sign_crypto_ops_t.
 *
 * @note A wrong digest here surfaces only as an opaque 403 from AWS, so this
 *       must pass the known-answer vectors in test_app before it is trusted.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include <string.h>
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"

_Static_assert(sizeof(psa_hash_operation_t) <= ESP_RMAKER_AWS_SIGN_SHA256_CTX_SIZE,
               "raise ESP_RMAKER_AWS_SIGN_SHA256_CTX_SIZE");

#define HMAC_BLOCK_LEN 64
#define HMAC_IPAD      0x36    /* RFC 2104 inner pad byte */
#define HMAC_OPAD      0x5c    /* RFC 2104 outer pad byte */

/* Idempotent, so an application that already initialised PSA is unaffected. */
static esp_err_t esp_crypto_init(void)
{
    return psa_crypto_init() == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

static esp_err_t esp_sha256_init(esp_rmaker_aws_sign_sha256_ctx_t *ctx)
{
    /* The core zeroes the storage first, which is PSA_HASH_OPERATION_INIT. */
    psa_hash_operation_t *op = (psa_hash_operation_t *)ctx->opaque;
    return psa_hash_setup(op, PSA_ALG_SHA_256) == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

static esp_err_t esp_sha256_update(esp_rmaker_aws_sign_sha256_ctx_t *ctx,
                                   const uint8_t *data, size_t len)
{
    psa_hash_operation_t *op = (psa_hash_operation_t *)ctx->opaque;
    return psa_hash_update(op, data, len) == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

static esp_err_t esp_sha256_finish(esp_rmaker_aws_sign_sha256_ctx_t *ctx, uint8_t out[32])
{
    psa_hash_operation_t *op = (psa_hash_operation_t *)ctx->opaque;
    size_t written = 0;
    /* psa_hash_finish() releases the operation on success and on failure. */
    if (psa_hash_finish(op, out, 32, &written) != PSA_SUCCESS || written != 32) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Tolerates an uninitialised context: an all-zero operation is inactive, and
 * aborting an inactive one succeeds. */
static void esp_sha256_abort(esp_rmaker_aws_sign_sha256_ctx_t *ctx)
{
    psa_hash_abort((psa_hash_operation_t *)ctx->opaque);
}

/* One RFC 2104 pass: H(pad || data). */
static psa_status_t hmac_pass(const uint8_t pad[HMAC_BLOCK_LEN], const uint8_t *data,
                              size_t data_len, uint8_t out[32])
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    psa_status_t status;
    do {
        status = psa_hash_setup(&op, PSA_ALG_SHA_256);
        if (status != PSA_SUCCESS) {
            break;
        }
        status = psa_hash_update(&op, pad, HMAC_BLOCK_LEN);
        if (status != PSA_SUCCESS) {
            break;
        }
        status = psa_hash_update(&op, data, data_len);
        if (status != PSA_SUCCESS) {
            break;
        }
        status = psa_hash_finish(&op, out, 32, &written);
    } while (0);
    psa_hash_abort(&op);
    return status;
}

/* RFC 2104 over psa_hash_*, since the PSA key store is unlocked without MBEDTLS_THREADING_C. */
static esp_err_t esp_hmac_sha256(const uint8_t *key, size_t key_len,
                                 const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint8_t pad[HMAC_BLOCK_LEN] = {0};
    uint8_t inner[32];
    psa_status_t status = PSA_SUCCESS;
    do {
        if (key_len > HMAC_BLOCK_LEN) {
            size_t written = 0;
            status = psa_hash_compute(PSA_ALG_SHA_256, key, key_len, pad, 32, &written);
            if (status != PSA_SUCCESS) {
                break;
            }
        } else if (key_len) {
            memcpy(pad, key, key_len);
        }
        for (int i = 0; i < HMAC_BLOCK_LEN; i++) {
            pad[i] ^= HMAC_IPAD;
        }
        status = hmac_pass(pad, msg, msg_len, inner);
        if (status != PSA_SUCCESS) {
            break;
        }
        for (int i = 0; i < HMAC_BLOCK_LEN; i++) {
            pad[i] ^= HMAC_IPAD ^ HMAC_OPAD;   /* K ^ ipad -> K ^ opad */
        }
        status = hmac_pass(pad, inner, sizeof(inner), out);
    } while (0);

    mbedtls_platform_zeroize(pad, sizeof(pad));
    mbedtls_platform_zeroize(inner, sizeof(inner));
    return status == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_crypto_ops_t esp_rmaker_aws_sign_esp_crypto_ops = {
    .init = esp_crypto_init,
    .sha256_init = esp_sha256_init,
    .sha256_update = esp_sha256_update,
    .sha256_finish = esp_sha256_finish,
    .sha256_abort = esp_sha256_abort,
    .hmac_sha256 = esp_hmac_sha256,
};
