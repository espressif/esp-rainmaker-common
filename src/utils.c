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
#include <esp_timer.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <esp_rmaker_common_events.h>

ESP_EVENT_DEFINE_BASE(RMAKER_COMMON_EVENT);

static esp_timer_handle_t reboot_timer;

static void esp_rmaker_reboot_cb(void *priv)
{
    esp_restart();
}

esp_err_t esp_rmaker_reboot(uint8_t seconds)
{
    if (reboot_timer) {
        return ESP_FAIL;
    }
    esp_timer_create_args_t reboot_timer_conf = {
        .callback = esp_rmaker_reboot_cb,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "rmaker_reboot_tm"
    };
    esp_err_t err = ESP_FAIL;
    if (esp_timer_create(&reboot_timer_conf, &reboot_timer) == ESP_OK) {
        err = esp_timer_start_once(reboot_timer, seconds * 1000000U);
    }
    if (err == ESP_OK) {
        esp_event_post(RMAKER_COMMON_EVENT, RMAKER_EVENT_REBOOT, &seconds, sizeof(seconds), portMAX_DELAY);
    }
    return err;
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
