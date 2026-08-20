/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file json.c
 * @brief cJSON implementation of esp_rmaker_aws_sign_json_ops_t.
 *
 * @note Adds what cJSON does not enforce: a duplicate requested key is refused,
 *       a non-string value is an error, and string contents are pre-screened.
 */

#include "esp_rmaker_aws_sign.h"
#include "esp_rmaker_aws_sign_esp_port.h"

#include <string.h>
#include "cJSON.h"

static bool is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* cJSON accepts two things the contract rejects, neither detectable afterwards:
 * an unescaped control character, and a \uXXXX it decodes to a 0x00 byte - from
 * U+0000 or invalid hex - which truncates the value it hands back. */
static bool strings_are_safe(const char *json, size_t len)
{
    bool in_string = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)json[i];
        if (!in_string) {
            in_string = (c == '"');             /* control chars are legal whitespace out here */
            continue;
        }
        if (c == '"') {
            in_string = false;
            continue;
        }
        if (c < 0x20) {
            return false;
        }
        if (c != '\\') {
            continue;
        }
        if (++i >= len) {
            return false;
        }
        if (json[i] != 'u') {
            continue;                           /* an escape pair, so \" does not end the string */
        }
        if (i + 4 >= len) {
            return false;
        }
        for (int d = 1; d <= 4; d++) {
            if (!is_hex(json[i + d])) {
                return false;
            }
        }
        if (memcmp(json + i + 1, "0000", 4) == 0) {
            return false;
        }
        i += 4;
    }
    return true;
}

/* Zero every string value before cJSON frees it: the tree holds credential copies. */
static void wipe_strings(cJSON *node)
{
    for (; node; node = node->next) {
        if (node->valuestring) {
            volatile char *p = node->valuestring;
            while (*p) {
                *p++ = '\0';
            }
        }
        wipe_strings(node->child);
    }
}

static void clear_fields(esp_rmaker_aws_sign_json_field_t fields[], size_t num)
{
    for (size_t i = 0; i < num; i++) {
        fields[i].found = false;
        fields[i].len = 0;
        if (fields[i].buf && fields[i].buf_size) {
            fields[i].buf[0] = '\0';
        }
    }
}

static esp_err_t esp_json_read_strs(const char *json, size_t len, const char *object,
                                    esp_rmaker_aws_sign_json_field_t fields[], size_t num)
{
    if (!json || !fields || num == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    clear_fields(fields, num);
    if (!strings_are_safe(json, len)) {
        return ESP_FAIL;
    }
    /* Length-bounded: the HTTP body is not NUL-terminated. */
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) {
        return ESP_FAIL;
    }

    esp_err_t err = ESP_FAIL;
    const cJSON *target = object ? cJSON_GetObjectItemCaseSensitive(root, object) : root;
    if (!cJSON_IsObject(target)) {
        goto out;
    }
    for (const cJSON *item = target->child; item; item = item->next) {
        if (!item->string) {
            continue;
        }
        size_t hit = num;
        for (size_t i = 0; i < num; i++) {
            if (fields[i].key && strcmp(fields[i].key, item->string) == 0) {
                hit = i;
                break;
            }
        }
        if (hit == num) {
            continue;                           /* not requested: ignored, duplicate or not */
        }
        if (fields[hit].found) {
            goto out;                           /* duplicate requested key */
        }
        if (!cJSON_IsString(item) || item->valuestring == NULL) {
            goto out;
        }
        size_t vlen = strlen(item->valuestring);
        if (!fields[hit].buf || vlen + 1 > fields[hit].buf_size) {
            goto out;                           /* never truncated */
        }
        memcpy(fields[hit].buf, item->valuestring, vlen + 1);
        fields[hit].len = vlen;
        fields[hit].found = true;
    }
    err = ESP_OK;

out:
    wipe_strings(root);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        clear_fields(fields, num);              /* fail closed */
    }
    return err;
}

/* The only exported symbol in this file. */
const esp_rmaker_aws_sign_json_ops_t esp_rmaker_aws_sign_esp_json_ops = {
    .read_strs = esp_json_read_strs,
};
