/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <esp_err.h>
#include <esp_event.h>
#include <esp_console.h>
#include <esp_idf_version.h>
#include <nvs_flash.h>
#include <sdkconfig.h>
#include <esp_rmaker_common_console.h>

#if CONFIG_ESP_RMAKER_CONSOLE_USE_REPL
#define CONSOLE_TYPE "repl"
#else
#define CONSOLE_TYPE "legacy"
#endif

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_rmaker_common_console_init());

    /* Deregister and register again, as an app does around a console restart */
    int ret = 0;
    esp_err_t dereg = esp_rmaker_common_deregister_commands();
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 0)
    bool removed = (dereg == ESP_OK) && (esp_console_run("up-time", &ret) == ESP_ERR_NOT_FOUND);
#else
    bool removed = (dereg == ESP_ERR_NOT_SUPPORTED);  /* the console cannot remove a command */
#endif
    esp_rmaker_common_register_commands();
    bool restored = (esp_console_run("up-time", &ret) == ESP_OK);
    printf("rmaker_console_test: re-register %s\n", (removed && restored) ? "ok" : "failed");
    /* pytest waits for this line before it sends commands, and reads the console type from it. */
    printf("rmaker_console_test: ready (" CONSOLE_TYPE ")\n");
}
