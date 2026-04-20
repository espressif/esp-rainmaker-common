/*
 * SPDX-FileCopyrightText: 2021-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sdkconfig.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/idf_additions.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_heap_caps.h>

#include <esp_rmaker_work_queue.h>

/* The Work Queue control block is small but long-lived, so prefer external RAM (SPIRAM)
 * when available, falling back to internal RAM. Only MEM_CALLOC_EXTRAM is used in this component. */
#if ((CONFIG_SPIRAM || CONFIG_SPIRAM_SUPPORT) && \
        (CONFIG_SPIRAM_USE_CAPS_ALLOC || CONFIG_SPIRAM_USE_MALLOC))
#define MEM_CALLOC_EXTRAM(num, size)   heap_caps_calloc_prefer(num, size, 2, MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL)
#else
#define MEM_CALLOC_EXTRAM(num, size)   calloc(num, size)
#endif

/* The option is SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY up to IDF 5.3, FREERTOS_TASK_CREATE_ALLOW_EXT_MEM from IDF 5.4 */
#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY || CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
#define WORK_QUEUE_EXT_RAM_STACK_ALLOWED 1
#else
#define WORK_QUEUE_EXT_RAM_STACK_ALLOWED 0
#endif

static const char *TAG = "esp_rmaker_work_queue";

typedef enum {
    WORK_QUEUE_STATE_DEINIT = 0,
    WORK_QUEUE_STATE_INIT_DONE,
    WORK_QUEUE_STATE_RUNNING,
    WORK_QUEUE_STATE_STOP_REQUESTED,
} esp_rmaker_work_queue_state_t;

typedef struct {
    esp_rmaker_work_fn_t work_fn;
    void *priv_data;
} esp_rmaker_work_queue_entry_t;

typedef struct esp_rmaker_work_queue {
    char name[configMAX_TASK_NAME_LEN];
    struct {
        QueueHandle_t queue;
        TaskHandle_t task;
    } handles;
    esp_rmaker_work_queue_config_t config;
    volatile esp_rmaker_work_queue_state_t state;
} esp_rmaker_work_queue_t;

static esp_rmaker_work_queue_t *g_work_queue = NULL;

static const esp_rmaker_work_queue_config_t g_work_queue_config = {
    .size = CONFIG_ESP_RMAKER_WORK_QUEUE_SIZE,
    .stack_size = CONFIG_ESP_RMAKER_WORK_QUEUE_TASK_STACK,
    .priority = CONFIG_ESP_RMAKER_WORK_QUEUE_TASK_PRIORITY,
    .prefer_ext_ram = ESP_RMAKER_WORK_QUEUE_PREFER_EXT_RAM_DEFAULT,
    .name = "rmaker_queue_task",
    .core_id = tskNO_AFFINITY,
};

static esp_err_t esp_rmaker_work_queue_stop_internal(esp_rmaker_work_queue_t *p_work_queue);

static void esp_rmaker_handle_work_queue(const esp_rmaker_work_queue_t *p_work_queue)
{
    esp_rmaker_work_queue_entry_t work_queue_entry;
    /* 2 sec delay to prevent spinning */
    BaseType_t ret = xQueueReceive(p_work_queue->handles.queue, &work_queue_entry, 2000 / portTICK_PERIOD_MS);
    while (ret == pdTRUE) {
        /* A NULL work_fn is the wake-up entry from stop */
        if (work_queue_entry.work_fn) {
            work_queue_entry.work_fn(work_queue_entry.priv_data);
        }
        ret = xQueueReceive(p_work_queue->handles.queue, &work_queue_entry, 0);
    }
}

static void esp_rmaker_work_queue_task(void *p_work_queue_arg)
{
    esp_rmaker_work_queue_t *p_work_queue = (esp_rmaker_work_queue_t *)p_work_queue_arg;
    if (!p_work_queue) {
        ESP_LOGE(TAG, "Invalid Work Queue pointer.");
        vTaskDelete(NULL);
    }
    const char *task_name = p_work_queue->name;
    for (;;) {
        ESP_LOGI(TAG, "RainMaker Work Queue task started for work queue '%s'.", task_name);
        while (p_work_queue->state != WORK_QUEUE_STATE_STOP_REQUESTED) {
            esp_rmaker_handle_work_queue(p_work_queue);
        }
        ESP_LOGI(TAG, "Stopping Work Queue task for work queue '%s'.", task_name);
        p_work_queue->state = WORK_QUEUE_STATE_INIT_DONE;

        /* Parked: start resumes the task, deinit deletes it */
        vTaskSuspend(NULL);
    }
}

static inline bool esp_rmaker_work_queue_is_own_worker(const esp_rmaker_work_queue_t *p_work_queue)
{
    return p_work_queue->handles.task && xTaskGetCurrentTaskHandle() == p_work_queue->handles.task;
}

static void esp_rmaker_work_queue_wait_stopped(const esp_rmaker_work_queue_t *p_work_queue)
{
    if (p_work_queue->state == WORK_QUEUE_STATE_STOP_REQUESTED) {
        ESP_LOGI(TAG, "Waiting for Work Queue '%s' to stop...", p_work_queue->name);
    }
    while (p_work_queue->state == WORK_QUEUE_STATE_STOP_REQUESTED) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (p_work_queue->handles.task) {
        /* On SMP the task can still be unwinding on the other core after it sets the state */
        while (eTaskGetState(p_work_queue->handles.task) != eSuspended) {
            vTaskDelay(1);
        }
    }
}

static esp_err_t esp_rmaker_work_queue_add_task_internal(esp_rmaker_work_queue_t *p_work_queue, esp_rmaker_work_fn_t work_fn, void *priv_data)
{
    if (!p_work_queue) {
        ESP_LOGE(TAG, "Cannot enqueue function as Work Queue hasn't been created.");
        return ESP_ERR_INVALID_STATE;
    }
    if (!work_fn) {
        ESP_LOGE(TAG, "work_fn cannot be NULL.");
        return ESP_ERR_INVALID_ARG;
    }
    esp_rmaker_work_queue_entry_t work_queue_entry = {
        .work_fn = work_fn,
        .priv_data = priv_data,
    };
    if (xQueueSend(p_work_queue->handles.queue, &work_queue_entry, 0) == pdTRUE) {
        return ESP_OK;
    }
    return ESP_FAIL;
}

static esp_err_t esp_rmaker_work_queue_init_internal(esp_rmaker_work_queue_t **pp_work_queue, const esp_rmaker_work_queue_config_t *p_config)
{
    if (!pp_work_queue || !p_config) {
        ESP_LOGE(TAG, "Invalid Work Queue pointer or configuration.");
        return ESP_ERR_INVALID_ARG;
    }

    /* Validate configuration */
    if (p_config->size == 0) {
        ESP_LOGE(TAG, "Invalid Work Queue size.");
        return ESP_ERR_INVALID_ARG;
    }
    if (p_config->stack_size == 0) {
        ESP_LOGE(TAG, "Invalid Work Queue stack size.");
        return ESP_ERR_INVALID_ARG;
    }
    if (p_config->priority == 0 || p_config->priority >= configMAX_PRIORITIES) {
        ESP_LOGE(TAG, "Invalid Work Queue priority.");
        return ESP_ERR_INVALID_ARG;
    }
    if (p_config->core_id != (BaseType_t)tskNO_AFFINITY &&
            (p_config->core_id < 0 || p_config->core_id >= portNUM_PROCESSORS)) {
        ESP_LOGE(TAG, "Invalid Work Queue core id.");
        return ESP_ERR_INVALID_ARG;
    }

    /* Create Work Queue */
    esp_err_t err = ESP_OK;
    esp_rmaker_work_queue_t *p_work_queue = (esp_rmaker_work_queue_t *)MEM_CALLOC_EXTRAM(1, sizeof(esp_rmaker_work_queue_t));
    if (!p_work_queue) {
        ESP_LOGE(TAG, "Failed to allocate memory for Work Queue.");
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    p_work_queue->handles.queue = xQueueCreate(p_config->size, sizeof(esp_rmaker_work_queue_entry_t));
    if (!p_work_queue->handles.queue) {
        ESP_LOGE(TAG, "Failed to create Work Queue.");
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    if (p_config->name) {
        strlcpy(p_work_queue->name, p_config->name, sizeof(p_work_queue->name));
    } else {
        /* Only feeds debug names, so a non-atomic counter is acceptable */
        static int work_queue_count = 0;
        snprintf(p_work_queue->name, sizeof(p_work_queue->name), "rmaker_wq-%d", work_queue_count++);
    }
    p_work_queue->config = *p_config;
    p_work_queue->config.name = NULL;
    ESP_LOGI(TAG, "Work Queue '%s' created.", p_work_queue->name);
    p_work_queue->state = WORK_QUEUE_STATE_INIT_DONE;
    *pp_work_queue = p_work_queue;
    return ESP_OK;

fail:
    if (p_work_queue) {
        if (p_work_queue->handles.queue) {
            vQueueDelete(p_work_queue->handles.queue);
            p_work_queue->handles.queue = NULL;
        }
        free(p_work_queue);
        p_work_queue = NULL;
    }
    return err;
}

static esp_err_t esp_rmaker_work_queue_deinit_internal(esp_rmaker_work_queue_t **pp_work_queue)
{
    if (!pp_work_queue) {
        ESP_LOGE(TAG, "Invalid Work Queue pointer.");
        return ESP_ERR_INVALID_ARG;
    }

    esp_rmaker_work_queue_t *p_work_queue = *pp_work_queue;
    if (!p_work_queue) {
        ESP_LOGD(TAG, "Work Queue not initialized.");
        return ESP_OK;
    }
    if (esp_rmaker_work_queue_is_own_worker(p_work_queue)) {
        ESP_LOGE(TAG, "Cannot deinit Work Queue '%s' from its own worker.", p_work_queue->name);
        return ESP_ERR_INVALID_STATE;
    }

    esp_rmaker_work_queue_stop_internal(p_work_queue);
    esp_rmaker_work_queue_wait_stopped(p_work_queue);

    /* Clean up task */
    if (p_work_queue->handles.task) {
#if WORK_QUEUE_EXT_RAM_STACK_ALLOWED
        vTaskDeleteWithCaps(p_work_queue->handles.task);
#else
        vTaskDelete(p_work_queue->handles.task);
#endif
        p_work_queue->handles.task = NULL;
    }

    /* Clean up queue */
    vQueueDelete(p_work_queue->handles.queue);
    p_work_queue->handles.queue = NULL;

    ESP_LOGI(TAG, "esp_rmaker_work_queue '%s' was successfully deinitialized", p_work_queue->name);
    free(p_work_queue);
    *pp_work_queue = NULL;
    return ESP_OK;
}

static esp_err_t esp_rmaker_work_queue_start_internal(esp_rmaker_work_queue_t *p_work_queue)
{
    if (!p_work_queue) {
        ESP_LOGE(TAG, "Work Queue not initialized.");
        return ESP_ERR_INVALID_STATE;
    }

    const char *task_name = p_work_queue->name;
    if (p_work_queue->state == WORK_QUEUE_STATE_RUNNING) {
        ESP_LOGW(TAG, "Work Queue '%s' already started.", task_name);
        return ESP_OK;
    }
    /* Resume the parked worker, so that one task serves the queue for its whole life */
    if (p_work_queue->handles.task) {
        if (esp_rmaker_work_queue_is_own_worker(p_work_queue)) {
            ESP_LOGE(TAG, "Cannot restart Work Queue '%s' from its own worker.", task_name);
            return ESP_ERR_INVALID_STATE;
        }
        esp_rmaker_work_queue_wait_stopped(p_work_queue);
        p_work_queue->state = WORK_QUEUE_STATE_RUNNING;
        vTaskResume(p_work_queue->handles.task);
        return ESP_OK;
    }
    if (p_work_queue->state != WORK_QUEUE_STATE_INIT_DONE) {
        ESP_LOGE(TAG, "Failed to start Work Queue '%s' as it wasn't initialized.", task_name);
        return ESP_ERR_INVALID_STATE;
    }

    BaseType_t ret = pdFAIL;
#if WORK_QUEUE_EXT_RAM_STACK_ALLOWED
    if (p_work_queue->config.prefer_ext_ram) {
        ret = xTaskCreatePinnedToCoreWithCaps(&esp_rmaker_work_queue_task, task_name, p_work_queue->config.stack_size, p_work_queue,
                                              p_work_queue->config.priority, &p_work_queue->handles.task, p_work_queue->config.core_id,
                                              MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    /* Internal RAM, or the fallback when external RAM is full */
    if (ret != pdPASS) {
        ret = xTaskCreatePinnedToCoreWithCaps(&esp_rmaker_work_queue_task, task_name, p_work_queue->config.stack_size, p_work_queue,
                                              p_work_queue->config.priority, &p_work_queue->handles.task, p_work_queue->config.core_id,
                                              MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
#else
    /* The build config forbids external-RAM task stacks, so keep the stack in internal RAM */
    if (p_work_queue->config.prefer_ext_ram) {
        ESP_LOGW(TAG, "prefer_ext_ram ignored (Work Queue: '%s'). Using SRAM! Enable CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM for ext_ram", task_name);
    }
    ret = xTaskCreatePinnedToCore(&esp_rmaker_work_queue_task, task_name, p_work_queue->config.stack_size, p_work_queue,
                                  p_work_queue->config.priority, &p_work_queue->handles.task, p_work_queue->config.core_id);
#endif
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Couldn't create RainMaker work queue task '%s'", task_name);
        return ESP_FAIL;
    }
    p_work_queue->state = WORK_QUEUE_STATE_RUNNING;
    return ESP_OK;
}

static esp_err_t esp_rmaker_work_queue_stop_internal(esp_rmaker_work_queue_t *p_work_queue)
{
    if (!p_work_queue) {
        ESP_LOGW(TAG, "Invalid Work Queue pointer, skipping stop.");
        return ESP_OK;
    }
    if (p_work_queue->state == WORK_QUEUE_STATE_RUNNING) {
        p_work_queue->state = WORK_QUEUE_STATE_STOP_REQUESTED;
        /* Wake the worker; if the queue is full, the worker is busy and sees the flag soon */
        const esp_rmaker_work_queue_entry_t wake_entry = { 0 };
        xQueueSend(p_work_queue->handles.queue, &wake_entry, 0);
    }
    return ESP_OK;
}

/* --- Global Work Queue --- */

esp_err_t esp_rmaker_work_queue_init(void)
{
    if (g_work_queue) {
        ESP_LOGW(TAG, "Work Queue already initialised.");
        return ESP_OK;
    }
    return esp_rmaker_work_queue_init_internal(&g_work_queue, &g_work_queue_config);
}

esp_err_t esp_rmaker_work_queue_deinit(void)
{
    return esp_rmaker_work_queue_deinit_internal(&g_work_queue);
}

esp_err_t esp_rmaker_work_queue_start(void)
{
    return esp_rmaker_work_queue_start_internal(g_work_queue);
}

esp_err_t esp_rmaker_work_queue_stop(void)
{
    return esp_rmaker_work_queue_stop_internal(g_work_queue);
}

esp_err_t esp_rmaker_work_queue_add_task(esp_rmaker_work_fn_t work_fn, void *priv_data)
{
    return esp_rmaker_work_queue_add_task_internal(g_work_queue, work_fn, priv_data);
}

/* --- Work Queue Instance --- */

esp_err_t esp_rmaker_work_queue_init_inst(esp_rmaker_work_queue_handle_t *p_handle, const esp_rmaker_work_queue_config_t *p_config)
{
    if (!p_handle) {
        ESP_LOGE(TAG, "Invalid Work Queue handle pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    if (!p_config) {
        ESP_LOGE(TAG, "Invalid Work Queue configuration pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    if (*p_handle != NULL) {
        ESP_LOGE(TAG, "Handle already initialised (or not set to NULL).");
        return ESP_ERR_INVALID_STATE;
    }
    return esp_rmaker_work_queue_init_internal(p_handle, p_config);
}

esp_err_t esp_rmaker_work_queue_deinit_inst(esp_rmaker_work_queue_handle_t *p_handle)
{
    if (!p_handle) {
        ESP_LOGE(TAG, "Invalid Work Queue handle pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    return esp_rmaker_work_queue_deinit_internal(p_handle);
}

esp_err_t esp_rmaker_work_queue_start_inst(esp_rmaker_work_queue_handle_t handle)
{
    if (!handle) {
        ESP_LOGE(TAG, "Invalid Work Queue handle pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    return esp_rmaker_work_queue_start_internal(handle);
}

esp_err_t esp_rmaker_work_queue_stop_inst(esp_rmaker_work_queue_handle_t handle)
{
    if (!handle) {
        ESP_LOGE(TAG, "Invalid Work Queue handle pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    return esp_rmaker_work_queue_stop_internal(handle);
}

esp_err_t esp_rmaker_work_queue_add_task_inst(esp_rmaker_work_queue_handle_t handle, esp_rmaker_work_fn_t work_fn, void *priv_data)
{
    if (!handle) {
        ESP_LOGE(TAG, "Invalid Work Queue handle pointer.");
        return ESP_ERR_INVALID_ARG;
    }
    return esp_rmaker_work_queue_add_task_internal(handle, work_fn, priv_data);
}
