// Copyright 2021 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <esp_sntp.h>

#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <esp_log.h>
#include <nvs.h>
#include <esp_rmaker_utils.h>
#include <esp_rmaker_common_events.h>
#include <esp_idf_version.h>

static const char *TAG = "esp_rmaker_time";

#define ESP_RMAKER_NVS_PART_NAME            "nvs"

#define ESP_RMAKER_NVS_TIME_NAMESPACE       "rmaker_time"
#define ESP_RMAKER_TZ_POSIX_NVS_NAME        "tz_posix"
#define ESP_RMAKER_TZ_NVS_NAME              "tz"

#define REF_TIME    1546300800 /* 01-Jan-2019 00:00:00 */
static bool init_done = false;
extern const char *esp_rmaker_tz_db_get_posix_str(const char *name);

#define ESP_RMAKER_DEF_TZ   CONFIG_ESP_RMAKER_DEF_TIMEZONE

int esp_setenv(const char *name, const char *value, int rewrite)
{
    return setenv(name, value, rewrite);
}

esp_err_t esp_rmaker_get_local_time_str(char *buf, size_t buf_len)
{
    struct tm timeinfo;
    char strftime_buf[64];
    time_t now;
    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c %z[%Z]", &timeinfo);
    size_t print_size = snprintf(buf, buf_len, "%s, DST: %s", strftime_buf, timeinfo.tm_isdst ? "Yes" : "No");
    if (print_size >= buf_len) {
        ESP_LOGE(TAG, "Buffer size %d insufficient for localtime string. Required size: %d", buf_len, print_size);
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static esp_err_t esp_rmaker_print_current_time(void)
{
    char local_time[64];
    if (esp_rmaker_get_local_time_str(local_time, sizeof(local_time)) == ESP_OK) {
        if (esp_rmaker_time_check() == false) {
            ESP_LOGI(TAG, "Time not synchronised yet.");
        }
        ESP_LOGI(TAG, "The current time is: %s.", local_time);
        return ESP_OK;
    }
    return ESP_FAIL;
}

static char *__esp_rmaker_time_get_nvs(const char *key)
{
    char *val = NULL;
    nvs_handle handle;
    esp_err_t err = nvs_open_from_partition(ESP_RMAKER_NVS_PART_NAME, ESP_RMAKER_NVS_TIME_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return NULL;
    }
    size_t len = 0;
    if ((err = nvs_get_blob(handle, key, NULL, &len)) == ESP_OK) {
        val = MEM_CALLOC_EXTRAM(1, len + 1); /* +1 for NULL termination */
        if (val) {
            nvs_get_blob(handle, key, val, &len);
        }
    }
    nvs_close(handle);
    return val;

}

static esp_err_t __esp_rmaker_time_set_nvs(const char *key, const char *val)
{
    nvs_handle handle;
    esp_err_t err = nvs_open_from_partition(ESP_RMAKER_NVS_PART_NAME, ESP_RMAKER_NVS_TIME_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(handle, key, val, strlen(val));
    nvs_commit(handle);
    nvs_close(handle);
    return err;
}

char *esp_rmaker_time_get_timezone_posix(void)
{
    return __esp_rmaker_time_get_nvs(ESP_RMAKER_TZ_POSIX_NVS_NAME);
}

char *esp_rmaker_time_get_timezone(void)
{
    return __esp_rmaker_time_get_nvs(ESP_RMAKER_TZ_NVS_NAME);
}

esp_err_t esp_rmaker_time_set_timezone_posix(const char *tz_posix)
{
    esp_err_t err = __esp_rmaker_time_set_nvs(ESP_RMAKER_TZ_POSIX_NVS_NAME, tz_posix);
    if (err == ESP_OK) {
        esp_setenv("TZ", tz_posix, 1);
        tzset();
        esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_TZ_POSIX_CHANGED,
                (void *)tz_posix, strlen(tz_posix) + 1, portMAX_DELAY);
        esp_rmaker_print_current_time();
    }
    return err;
}

esp_err_t esp_rmaker_time_set_timezone(const char *tz)
{
    const char *tz_posix = esp_rmaker_tz_db_get_posix_str(tz);
    if (!tz_posix) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = esp_rmaker_time_set_timezone_posix(tz_posix);
    if (err == ESP_OK) {
        esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_TZ_CHANGED, (void *)tz,
                strlen(tz) + 1, portMAX_DELAY);
        err = __esp_rmaker_time_set_nvs(ESP_RMAKER_TZ_NVS_NAME, tz);
    }
    return err;
}

esp_err_t esp_rmaker_timezone_enable(void)
{
    char *tz_posix = esp_rmaker_time_get_timezone_posix();
    if (tz_posix) {
        esp_setenv("TZ", tz_posix, 1);
        tzset();
        free(tz_posix);
    } else {
        if (strlen(ESP_RMAKER_DEF_TZ) > 0) {
            const char *tz_def = esp_rmaker_tz_db_get_posix_str(ESP_RMAKER_DEF_TZ);
            if (tz_def) {
                esp_setenv("TZ", tz_def, 1);
                tzset();
                return ESP_OK;
            } else {
                ESP_LOGE(TAG, "Invalid Timezone %s specified.", ESP_RMAKER_DEF_TZ);
                return ESP_ERR_INVALID_ARG;
            }
        }
    }
    return ESP_OK;
}
static void esp_rmaker_time_sync_cb(struct timeval *tv)
{
    ESP_LOGI(TAG, "SNTP Synchronised.");
    esp_rmaker_print_current_time();
}

esp_err_t esp_rmaker_time_sync_init(esp_rmaker_time_config_t *config)
{
    if (esp_sntp_enabled()) {
        ESP_LOGI(TAG, "SNTP already initialized.");
        init_done = true;
        return ESP_OK;
    }
    char *sntp_server_name;
    if (!config || !config->sntp_server_name) {
        sntp_server_name = CONFIG_ESP_RMAKER_SNTP_SERVER_NAME;
    } else {
        sntp_server_name = config->sntp_server_name;
    }
    ESP_LOGI(TAG, "Initializing SNTP. Using the SNTP server: %s", sntp_server_name);
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, sntp_server_name);
    esp_sntp_init();
    if (config && config->sync_time_cb) {
        sntp_set_time_sync_notification_cb(config->sync_time_cb);
    } else {
        sntp_set_time_sync_notification_cb(esp_rmaker_time_sync_cb);
    }
    esp_rmaker_timezone_enable();
    init_done = true;
    return ESP_OK;
}

bool esp_rmaker_time_check(void)
{
    time_t now;
    time(&now);
    if (now > REF_TIME) {
        return true;
    }
    return false;
}


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

/* ---- UTC converter with no setenv/timegm dependency ---- */
static inline int is_leap(int y) {
    return ((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0);
}

/* Interprets tm as UTC and returns epoch seconds */
static inline time_t rmaker_timegm(struct tm *tm)
{
    /* Normalize month to [0,11] */
    int year  = tm->tm_year + 1900;
    int month = tm->tm_mon;
    if (month < 0) { year += (month - 11) / 12; month = 12 + (month % 12); }
    else if (month > 11) { year += month / 12; month %= 12; }

    static const int mdays_cum[12] = {0,31,59,90,120,151,181,212,243,273,304,334};

    int64_t days = 0;
    if (year >= 1970) for (int y = 1970; y < year; ++y) days += 365 + is_leap(y);
    else              for (int y = year;  y < 1970; ++y) days -= 365 + is_leap(y);

    days += mdays_cum[month];
    if (month > 1 && is_leap(year)) days += 1;
    days += (tm->tm_mday - 1);

    int64_t seconds = days * 86400LL
                    + (int64_t)tm->tm_hour * 3600
                    + (int64_t)tm->tm_min  * 60
                    + (int64_t)tm->tm_sec;

    return (time_t)seconds;
}

/* Supports "YYYY-MM-DDTHH:MM:SSZ" and "YYYY-MM-DDTHH:MM:SS[+-]HH:MM" */
time_t iso8601_to_epoch(const char *iso_string) {
    struct tm tm_info = {0};
    int year, month, day, hour, minute, second;
    int tz_hour = 0, tz_minute = 0;
    char tz_sign = '+';

    if (sscanf(iso_string, "%d-%d-%dT%d:%d:%d%c%d:%d",
               &year, &month, &day, &hour, &minute, &second,
               &tz_sign, &tz_hour, &tz_minute) == 9) {
        /* parsed with offset */
    } else if (sscanf(iso_string, "%d-%d-%dT%d:%d:%dZ",
                      &year, &month, &day, &hour, &minute, &second) == 6) {
        tz_hour = 0; tz_minute = 0; tz_sign = '+';
    } else {
        ESP_LOGE(TAG, "Error: Invalid ISO 8601 format.\n");
        return (time_t)-1;
    }

    tm_info.tm_year  = year - 1900;
    tm_info.tm_mon   = month - 1;
    tm_info.tm_mday  = day;
    tm_info.tm_hour  = hour;
    tm_info.tm_min   = minute;
    tm_info.tm_sec   = second;
    tm_info.tm_isdst = -1; /* let system decide DST for this broken-down time */

    /* Interpret parsed wall-clock as system-local */
    time_t local_epoch = mktime(&tm_info);
    if (local_epoch == (time_t)-1) {
        ESP_LOGE(TAG, "Error: mktime() failed.\n");
        return (time_t)-1;
    }

    /* Compute system offset (local - UTC) at that instant WITHOUT touching TZ */
    struct tm tmp_local;
    localtime_r(&local_epoch, &tmp_local);
    tmp_local.tm_isdst = -1;                   /* recompute DST if needed */
    /* Treat the same wall-clock fields as if they were UTC: */
    time_t utc_from_local_as_utc = rmaker_timegm(&tmp_local);
    int64_t sys_offset = (int64_t)utc_from_local_as_utc - (int64_t)local_epoch;

    /* parsed offset (timestamp's zone) */
    int64_t parsed_offset = (int64_t)tz_hour * 3600 + (int64_t)tz_minute * 60;
    if (tz_sign == '-') parsed_offset = -parsed_offset;

    /* FINAL: Add the system-local offset and the parsed offset (timezone offset) */
    int64_t final_epoch64 = (int64_t)local_epoch + sys_offset - parsed_offset;
    return (time_t)final_epoch64;
}

esp_err_t esp_rmaker_time_convert_iso8601_to_epoch(const char *str, int len, time_t *out_epoch)
{
    if (!str || !out_epoch) {
        return ESP_FAIL;
    }

    char buf[64];
    int copy_len = 0;
    if (len > 0) {
        copy_len = (len < (int)sizeof(buf) - 1) ? len : (int)sizeof(buf) - 1;
    } else {
        size_t str_len = strlen(str);
        copy_len = (str_len < sizeof(buf) - 1) ? (int)str_len : (int)sizeof(buf) - 1;
    }
    memcpy(buf, str, copy_len);
    buf[copy_len] = '\0';

    struct tm tm_utc = {0};
    int year, month, day, hour, minute, second;
    int tz_hour = 0, tz_minute = 0;
    char tz_sign = '+';

    /* Number of fields expected for each format */
    #define ISO8601_WITH_TIMEZONE_FIELDS    9  /* year, month, day, hour, minute, second, tz_sign, tz_hour, tz_minute */
    #define ISO8601_UTC_FIELDS              6  /* year, month, day, hour, minute, second */

    /* Try parsing with timezone offset: "YYYY-MM-DDTHH:MM:SS[+-]HH:MM" */
    if (sscanf(buf, "%d-%d-%dT%d:%d:%d%c%d:%d",
               &year, &month, &day, &hour, &minute, &second,
               &tz_sign, &tz_hour, &tz_minute) == ISO8601_WITH_TIMEZONE_FIELDS) {
        /* Timezone offset format parsed successfully */
    } else if (sscanf(buf, "%d-%d-%dT%d:%d:%dZ",
                      &year, &month, &day, &hour, &minute, &second) == ISO8601_UTC_FIELDS) {
        /* UTC format - validate that 'Z' is present at position 19 */
        size_t buf_len = strlen(buf);
        if (buf_len < 20 || buf[19] != 'Z') {
            ESP_LOGE(TAG, "Invalid ISO 8601 format: '%s' (missing Z suffix)", buf);
            return ESP_FAIL;
        }
        tz_hour = 0;
        tz_minute = 0;
        tz_sign = '+';
    } else {
        ESP_LOGE(TAG, "Invalid ISO 8601 format: '%s'", buf);
        return ESP_FAIL;
    }

    /* Fill tm structure with parsed values */
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon = month - 1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = minute;
    tm_utc.tm_sec = second;
    tm_utc.tm_isdst = 0; /* No DST in UTC */

    /* Calculate timezone offset in seconds */
    int total_offset_seconds = (tz_hour * 3600) + (tz_minute * 60);
    if (tz_sign == '-') {
        total_offset_seconds = -total_offset_seconds;
    }

    /* Convert to epoch time using timezone-independent rmaker_timegm */
    time_t utc_epoch = rmaker_timegm(&tm_utc);
    if (utc_epoch == (time_t)-1) {
        ESP_LOGE(TAG, "rmaker_timegm failed");
        return ESP_FAIL;
    }

    /* Adjust for timezone offset to get true epoch time */
    *out_epoch = utc_epoch - total_offset_seconds;

    return ESP_OK;
}

#define DEFAULT_TICKS   (2000 / portTICK_PERIOD_MS) /* 2 seconds in ticks */

esp_err_t esp_rmaker_time_wait_for_sync(uint32_t ticks_to_wait)
{
    if (!init_done) {
        ESP_LOGW(TAG, "Time sync not initialized using 'esp_rmaker_time_sync_init'");
    }
    ESP_LOGW(TAG, "Waiting for time to be synchronized. This may take time.");
    uint32_t ticks_remaining = ticks_to_wait;
    uint32_t ticks = DEFAULT_TICKS;
    while (ticks_remaining > 0) {
        if (esp_rmaker_time_check() == true) {
            break;
        }
        ESP_LOGD(TAG, "Time not synchronized yet. Retrying...");
        ticks = ticks_remaining < DEFAULT_TICKS ? ticks_remaining : DEFAULT_TICKS;
        ticks_remaining -= ticks;
        vTaskDelay(ticks);
    }

    /* Check if ticks_to_wait expired and time is not synchronized yet. */
    if (esp_rmaker_time_check() == false) {
        ESP_LOGE(TAG, "Time not synchronized within the provided ticks: %" PRIu32, ticks_to_wait);
        return ESP_FAIL;
    }

    /* Get current time */
    esp_rmaker_print_current_time();
    return ESP_OK;
}
