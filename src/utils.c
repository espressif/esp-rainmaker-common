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
#include <stdint.h>
#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <esp_rmaker_common_events.h>

ESP_EVENT_DEFINE_BASE(RMAKER_COMMON_EVENT);

static TimerHandle_t reboot_timer;

static void esp_rmaker_reboot_cb(TimerHandle_t handle)
{
    xTimerDelete(reboot_timer, 10);
    reboot_timer = NULL;
    esp_restart();
}

esp_err_t esp_rmaker_reboot(uint8_t seconds)
{
    /* If reboot timer already exists, it means that a reboot operation is already in progress.
     * So, just return an error from here.
     */
    if (reboot_timer) {
        return ESP_FAIL;
    }
    reboot_timer = xTimerCreate("rmaker_reboot_tm", (seconds * 1000) / portTICK_PERIOD_MS,
                            pdFALSE, NULL, esp_rmaker_reboot_cb);
    if (reboot_timer) {
        if (xTimerStart(reboot_timer, 10) != pdTRUE) {
            xTimerDelete(reboot_timer, 10);
            reboot_timer = NULL;
            return ESP_FAIL;
        }
    } else {
        return ESP_ERR_NO_MEM;
    }
    esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_REBOOT, &seconds, sizeof(seconds), portMAX_DELAY);
    return ESP_OK;
}

esp_err_t esp_rmaker_wifi_reset(uint8_t seconds)
{
    esp_wifi_restore();
    esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_WIFI_RESET, NULL, 0, portMAX_DELAY);
    return esp_rmaker_reboot(seconds);
}

esp_err_t esp_rmaker_factory_reset(uint8_t seconds)
{
    nvs_flash_deinit();
    nvs_flash_erase();
    esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_FACTORY_RESET, NULL, 0, portMAX_DELAY);
    return esp_rmaker_reboot(seconds);
}
