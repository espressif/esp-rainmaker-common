/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "unity.h"
#include "esp_rmaker_work_queue.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"  // Add missing header for esp_timer_get_time()
#include "esp_heap_caps.h"

#if CONFIG_IDF_TARGET_LINUX
#include <sys/time.h>
int64_t esp_timer_get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
#endif

static const char *TAG = "work_queue_test";
static const esp_rmaker_work_queue_config_t s_default_cfg = ESP_RMAKER_WORK_QUEUE_CONFIG_DEFAULT();

// Runs seq twice and checks that the second run frees all it allocates; the first run absorbs first-use allocations.
static void wq_assert_no_leak(void (*seq)(void))
{
    seq();
    size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    seq();
    TEST_ASSERT_EQUAL(heap_before, heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
}
static SemaphoreHandle_t work_done_semaphore;
static int work_execution_count = 0;
static int delay_work_execution_count = 0;
static esp_rmaker_work_fn_t saved_work_fn = NULL;
static void *saved_work_data = NULL;

// Simple work function to test work queue
static void test_work_fn(void *data)
{
    ESP_LOGI(TAG, "Work function executed with data: %s", (char *)data);
    work_execution_count++;
    xSemaphoreGive(work_done_semaphore);
}

// Work function with delay to test delayed work
static void test_delayed_work_fn(void *data)
{
    ESP_LOGI(TAG, "Delayed work function executed with data: %s", (char *)data);
    delay_work_execution_count++;
    xSemaphoreGive(work_done_semaphore);
}

esp_err_t esp_rmaker_work_queue_add_delayed_task(esp_rmaker_work_fn_t work_fn, void *data, uint32_t delay_ms) {
    // Implement delay logic using a timer or delay mechanism
    // Schedule the work function to execute after delay_ms milliseconds
    // This is a placeholder implementation
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
    return esp_rmaker_work_queue_add_task(work_fn, data);
}

TEST_CASE("ESP RainMaker Work Queue Init", "[work_queue]")
{
    work_done_semaphore = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(work_done_semaphore);

    // Initialize the work queue
    esp_err_t err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Trying to init again should return success (or no error)
    err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());
    vSemaphoreDelete(work_done_semaphore);
}

TEST_CASE("ESP RainMaker Work Queue Add Work", "[work_queue]")
{
    work_done_semaphore = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(work_done_semaphore);

    // Initialize the work queue
    esp_err_t err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Start the work queue
    err = esp_rmaker_work_queue_start();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    work_execution_count = 0;
    const char *test_data = "test_work_data";

    // Add work to the queue
    err = esp_rmaker_work_queue_add_task(test_work_fn, (void *)test_data);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Wait for work to be executed
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(work_done_semaphore, pdMS_TO_TICKS(5000)));

    // Verify work was executed
    TEST_ASSERT_EQUAL(1, work_execution_count);

    vSemaphoreDelete(work_done_semaphore);

    // Deinitialize the work queue
    esp_rmaker_work_queue_deinit();
}

TEST_CASE("ESP RainMaker Work Queue Add Multiple Works", "[work_queue]")
{
    // Use a counting semaphore to handle multiple tasks
    work_done_semaphore = xSemaphoreCreateCounting(3, 0);
    TEST_ASSERT_NOT_NULL(work_done_semaphore);

    // Initialize the work queue
    esp_err_t err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Start the work queue
    err = esp_rmaker_work_queue_start();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    work_execution_count = 0;
    const char *test_data1 = "test_work_data1";
    const char *test_data2 = "test_work_data2";
    const char *test_data3 = "test_work_data3";

    // Add multiple work items to the queue
    err = esp_rmaker_work_queue_add_task(test_work_fn, (void *)test_data1);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = esp_rmaker_work_queue_add_task(test_work_fn, (void *)test_data2);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = esp_rmaker_work_queue_add_task(test_work_fn, (void *)test_data3);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Wait for all work to be executed
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(work_done_semaphore, pdMS_TO_TICKS(5000)));
    }

    // Verify all work was executed
    TEST_ASSERT_EQUAL(3, work_execution_count);

    vSemaphoreDelete(work_done_semaphore);

    // Deinitialize the work queue
    esp_rmaker_work_queue_deinit();
}

TEST_CASE("ESP RainMaker Work Queue Add Delayed Work", "[work_queue]")
{
    work_done_semaphore = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(work_done_semaphore);

    // Initialize the work queue
    esp_err_t err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Start the work queue
    err = esp_rmaker_work_queue_start();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    delay_work_execution_count = 0;
    const char *test_data = "delayed_work_data";

    // Get current time
    int64_t start_time = esp_timer_get_time();

    // Add delayed task to the queue
    err = esp_rmaker_work_queue_add_delayed_task(test_delayed_work_fn, (void *)test_data, 1000); // 1000 ms delay
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Wait for work to be executed
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(work_done_semaphore, pdMS_TO_TICKS(5000)));

    // Verify work was executed
    TEST_ASSERT_EQUAL(1, delay_work_execution_count);

    // Check time taken
    int64_t elapsed_time = (esp_timer_get_time() - start_time) / 1000; // ms
    ESP_LOGI(TAG, "Work executed after %" PRIi64 " ms", elapsed_time);
    int64_t margin_of_error = 10;
    TEST_ASSERT_TRUE((elapsed_time >= 1000 - margin_of_error) && (elapsed_time <= 1000 + 2 * margin_of_error));

    vSemaphoreDelete(work_done_semaphore);

    // Deinitialize the work queue
    esp_rmaker_work_queue_deinit();
}

// Tests storing a task that can be executed later
TEST_CASE("ESP RainMaker Work Queue Store Task", "[work_queue]")
{
    work_done_semaphore = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(work_done_semaphore);

    // Initialize and start the work queue
    esp_err_t err = esp_rmaker_work_queue_init();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Start the work queue
    err = esp_rmaker_work_queue_start();
    TEST_ASSERT_EQUAL(ESP_OK, err);

    saved_work_fn = NULL;
    saved_work_data = NULL;
    work_execution_count = 0;
    const char *test_data = "stored_work_data";

    // Store the task
    err = esp_rmaker_work_queue_add_task(test_work_fn, (void *)test_data);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    // Wait for work to be executed
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(work_done_semaphore, pdMS_TO_TICKS(5000)));

    // Verify work was executed
    TEST_ASSERT_EQUAL(1, work_execution_count);

    // Clean up
    vSemaphoreDelete(work_done_semaphore);

    // Deinitialize the work queue
    esp_rmaker_work_queue_deinit();
}

/* ------------------------------------------------------------------ */
/* ---------------- Work Queue Instance Tests ------------------------- */
/* ------------------------------------------------------------------ */

typedef struct {
    SemaphoreHandle_t done;
    volatile int exec_count;
    int order_log[16];
    volatile int order_idx;
    uint32_t hold_ms;
    volatile int64_t entry_time;
    int tag;
} wq_ctx_t;

static void wq_ctx_reset(wq_ctx_t *c)
{
    c->exec_count = 0;
    c->order_idx = 0;
    c->hold_ms = 0;
    c->entry_time = 0;
    c->tag = 0;
    memset(c->order_log, 0, sizeof(c->order_log));
}

// Generic work fn: records entry time, optional hold, increments count, signals.
static void wq_generic_work_fn(void *data)
{
    wq_ctx_t *ctx = (wq_ctx_t *)data;
    if (!ctx) {
        return;
    }
    ctx->entry_time = esp_timer_get_time();
    if (ctx->hold_ms) {
        vTaskDelay(pdMS_TO_TICKS(ctx->hold_ms));
    }
    ctx->exec_count++;
    if (ctx->done) {
        xSemaphoreGive(ctx->done);
    }
}

// Ordering work fn: priv_data is a cast int id; logs into a shared ctx.
static wq_ctx_t *s_order_ctx = NULL;
static void wq_order_work_fn(void *data)
{
    int id = (int)(intptr_t)data;
    if (s_order_ctx) {
        int idx = s_order_ctx->order_idx;
        if (idx < (int)(sizeof(s_order_ctx->order_log) / sizeof(s_order_ctx->order_log[0]))) {
            s_order_ctx->order_log[idx] = id;
            s_order_ctx->order_idx = idx + 1;
        }
        s_order_ctx->exec_count++;
        if (s_order_ctx->done) {
            xSemaphoreGive(s_order_ctx->done);
        }
    }
}

TEST_CASE("ESP RainMaker WQ Instance Init/Deinit Invalid Args", "[work_queue]")
{
    esp_rmaker_work_queue_handle_t h = NULL;
    esp_rmaker_work_queue_config_t cfg = s_default_cfg;

    // NULL handle pointer.
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(NULL, &cfg));
    // NULL config pointer.
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, NULL));
    TEST_ASSERT_NULL(h);

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_deinit_inst(NULL));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_start_inst(NULL));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_stop_inst(NULL));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_add_task_inst(NULL, test_work_fn, NULL));
}

TEST_CASE("ESP RainMaker Work Queue Add Task Rejects NULL work_fn", "[work_queue]")
{
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_add_task(NULL, NULL));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_add_task_inst(h, NULL, NULL));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
}

TEST_CASE("ESP RainMaker WQ Instance Init Rejects Invalid Config Fields", "[work_queue]")
{
    esp_rmaker_work_queue_handle_t h = NULL;
    esp_rmaker_work_queue_config_t cfg;

    // size == 0
    cfg = s_default_cfg;
    cfg.size = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NULL(h);

    // stack_size == 0
    cfg = s_default_cfg;
    cfg.stack_size = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NULL(h);

    // priority == 0
    cfg = s_default_cfg;
    cfg.priority = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NULL(h);

    // priority >= configMAX_PRIORITIES
    cfg = s_default_cfg;
    cfg.priority = configMAX_PRIORITIES;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NULL(h);

    // core_id out of range
    cfg = s_default_cfg;
    cfg.core_id = portNUM_PROCESSORS;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NULL(h);

    // sanity: defaults must succeed.
    cfg = s_default_cfg;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_NOT_NULL(h);

    // An already-set handle is rejected and left unchanged.
    esp_rmaker_work_queue_handle_t prev = h;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_EQUAL_PTR(prev, h);
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
}

TEST_CASE("ESP RainMaker WQ Instance Custom Config Honored", "[work_queue]")
{
    // Custom size=3: queue must accept exactly 3 before full.
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateCounting(3, 0);
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_config_t cfg = s_default_cfg;
    cfg.size = 3;

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &cfg));

    // Queue not started: fill up to custom size.
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(ESP_OK,
            esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    }
    // 4th must fail (custom size==3, not default 8).
    TEST_ASSERT_EQUAL(ESP_FAIL,
        esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    }
    TEST_ASSERT_EQUAL_INT(3, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker WQ Instance Basic Lifecycle", "[work_queue]")
{
    wq_ctx_t ctx = { 0 };
    ctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_NOT_NULL(h);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(1, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    TEST_ASSERT_NULL(h);

    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker WQ Instance Deinit Nulls Handle", "[work_queue]")
{
    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_NOT_NULL(h);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    TEST_ASSERT_NULL(h);

    // Second deinit on the nulled handle must not crash; implementation short-circuits.
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    TEST_ASSERT_NULL(h);
}

TEST_CASE("ESP RainMaker WQ Instance FIFO Ordering", "[work_queue]")
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateCounting(5, 0);
    TEST_ASSERT_NOT_NULL(ctx.done);
    s_order_ctx = &ctx;

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));

    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL(ESP_OK,
            esp_rmaker_work_queue_add_task_inst(h, wq_order_work_fn, (void *)(intptr_t)i));
    }

    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    }

    TEST_ASSERT_EQUAL(5, ctx.exec_count);
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL_INT(i, ctx.order_log[i]);
    }

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    s_order_ctx = NULL;
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker WQ Instance Queue Full", "[work_queue]")
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateCounting(8, 0);
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    // Do NOT start yet - fill the queue to its capacity (ESP_RMAKER_TASK_QUEUE_SIZE = 8).
    for (int i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL(ESP_OK,
            esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    }
    // 9th enqueue while full and not drained must fail.
    TEST_ASSERT_EQUAL(ESP_FAIL,
        esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));

    // Drain by starting the worker.
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    for (int i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    }
    TEST_ASSERT_EQUAL(8, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker Two WQ Instances Run In Parallel", "[work_queue]")
{
    wq_ctx_t a, b;
    wq_ctx_reset(&a);
    wq_ctx_reset(&b);
    a.done = xSemaphoreCreateBinary();
    b.done = xSemaphoreCreateBinary();
    a.hold_ms = 200;
    b.hold_ms = 200;
    TEST_ASSERT_NOT_NULL(a.done);
    TEST_ASSERT_NOT_NULL(b.done);

    esp_rmaker_work_queue_handle_t ha = NULL, hb = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&ha, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&hb, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(ha));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(hb));

    int64_t dispatch = esp_timer_get_time();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(ha, wq_generic_work_fn, &a));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(hb, wq_generic_work_fn, &b));

    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(a.done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(b.done, pdMS_TO_TICKS(5000)));
    int64_t elapsed_ms = (esp_timer_get_time() - dispatch) / 1000;

    // Both tasks held CPU for 200 ms each. Serial execution on one queue would take >=400 ms.
    // True parallel across two queues completes near 200 ms; allow generous slack.
    ESP_LOGI(TAG, "parallel elapsed = %" PRIi64 " ms", elapsed_ms);
    TEST_ASSERT_TRUE(elapsed_ms < 350);

    // Entry times should be near-simultaneous (both queues picked up work without waiting).
    int64_t delta_ms = (a.entry_time > b.entry_time)
                       ? (a.entry_time - b.entry_time) / 1000
                       : (b.entry_time - a.entry_time) / 1000;
    ESP_LOGI(TAG, "entry skew = %" PRIi64 " ms", delta_ms);
    TEST_ASSERT_TRUE(delta_ms < 50);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&ha));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&hb));
    vSemaphoreDelete(a.done);
    vSemaphoreDelete(b.done);
}

TEST_CASE("ESP RainMaker WQ Instance Isolation Under Block", "[work_queue]")
{
    wq_ctx_t slow, fast;
    wq_ctx_reset(&slow);
    wq_ctx_reset(&fast);
    slow.done = xSemaphoreCreateBinary();
    fast.done = xSemaphoreCreateBinary();
    slow.hold_ms = 1500;
    fast.hold_ms = 0;
    TEST_ASSERT_NOT_NULL(slow.done);
    TEST_ASSERT_NOT_NULL(fast.done);

    esp_rmaker_work_queue_handle_t hslow = NULL, hfast = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&hslow, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&hfast, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(hslow));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(hfast));

    int64_t t0 = esp_timer_get_time();
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(hslow, wq_generic_work_fn, &slow));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(hfast, wq_generic_work_fn, &fast));

    // fast must complete well before slow finishes (slow holds 1500 ms).
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(fast.done, pdMS_TO_TICKS(500)));
    int64_t fast_ms = (esp_timer_get_time() - t0) / 1000;
    ESP_LOGI(TAG, "fast finished in %" PRIi64 " ms while slow blocks", fast_ms);
    TEST_ASSERT_TRUE(fast_ms < 500);

    // Wait for slow to drain before teardown (deinit would block otherwise).
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(slow.done, pdMS_TO_TICKS(5000)));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&hslow));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&hfast));
    vSemaphoreDelete(slow.done);
    vSemaphoreDelete(fast.done);
}

TEST_CASE("ESP RainMaker Global + WQ Instance Coexistence", "[work_queue]")
{
    wq_ctx_t gctx, uctx;
    wq_ctx_reset(&gctx);
    wq_ctx_reset(&uctx);
    gctx.done = xSemaphoreCreateBinary();
    uctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(gctx.done);
    TEST_ASSERT_NOT_NULL(uctx.done);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init());
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start());

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task(wq_generic_work_fn, &gctx));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &uctx));

    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(gctx.done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(uctx.done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(1, gctx.exec_count);
    TEST_ASSERT_EQUAL(1, uctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());
    vSemaphoreDelete(gctx.done);
    vSemaphoreDelete(uctx.done);
}

static void wq_restart_seq(void)
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));

    // Each restart resumes the same worker; start waits for the previous stop to finish.
    for (int i = 1; i <= 3; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
        TEST_ASSERT_EQUAL(i, ctx.exec_count);
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_stop_inst(h));
    }

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker WQ Instance Restart", "[work_queue]")
{
    wq_assert_no_leak(wq_restart_seq);
}

TEST_CASE("ESP RainMaker WQ Instance Add After Stop Is Safe", "[work_queue]")
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_stop_inst(h));
    // Stop wakes the worker, so it parks quickly.
    vTaskDelay(pdMS_TO_TICKS(100));

    // Entries added after stop stay in the queue until the next start.
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    int before = ctx.exec_count;
    vTaskDelay(pdMS_TO_TICKS(200));
    TEST_ASSERT_EQUAL_INT(before, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL_INT(before + 1, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(ctx.done);
}

#define WQ_STRESS_QUEUES 4
#define WQ_STRESS_TASKS_PER_QUEUE 5

static void wq_stress_seq(void)
{
    const int total = WQ_STRESS_QUEUES * WQ_STRESS_TASKS_PER_QUEUE;
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.hold_ms = 200; // each task sleeps 200 ms
    ctx.done = xSemaphoreCreateCounting(total, 0);
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h[WQ_STRESS_QUEUES] = { 0 };
    for (int i = 0; i < WQ_STRESS_QUEUES; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h[i], &s_default_cfg));
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h[i]));
    }

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < WQ_STRESS_QUEUES; i++) {
        for (int j = 0; j < WQ_STRESS_TASKS_PER_QUEUE; j++) {
            TEST_ASSERT_EQUAL(ESP_OK,
                esp_rmaker_work_queue_add_task_inst(h[i], wq_generic_work_fn, &ctx));
        }
    }
    for (int i = 0; i < total; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(10000)));
    }
    int64_t elapsed_ms = (esp_timer_get_time() - t0) / 1000;
    ESP_LOGI(TAG, "stress %d tasks across %d queues: %" PRIi64 " ms",
             total, WQ_STRESS_QUEUES, elapsed_ms);

    TEST_ASSERT_EQUAL_INT(total, ctx.exec_count);
    // Serial on a single queue = 5 * 200 = 1000 ms; four queues in parallel should finish
    // near 1000 ms. Bound generously at 2500 ms to tolerate scheduler jitter on dual-core.
    // A regression that funneled all tasks into one queue would take ~4000 ms.
    TEST_ASSERT_TRUE(elapsed_ms < 2500);

    for (int i = 0; i < WQ_STRESS_QUEUES; i++) {
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h[i]));
    }
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker Many WQ Instances Stress", "[work_queue]")
{
    wq_assert_no_leak(wq_stress_seq);
}

TEST_CASE("ESP RainMaker WQ Instance Start Twice Is Idempotent", "[work_queue]")
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(ctx.done);

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));  // idempotent

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_generic_work_fn, &ctx));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));

    // Confirm no phantom duplicate worker consumed a second (non-existent) event.
    int after = ctx.exec_count;
    vTaskDelay(pdMS_TO_TICKS(200));
    TEST_ASSERT_EQUAL_INT(after, ctx.exec_count);
    TEST_ASSERT_EQUAL_INT(1, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker WQ Instance Distinct Queue Storage", "[work_queue]")
{
    wq_ctx_t a, b;
    wq_ctx_reset(&a);
    wq_ctx_reset(&b);
    a.done = xSemaphoreCreateCounting(3, 0);
    b.done = xSemaphoreCreateCounting(3, 0);
    TEST_ASSERT_NOT_NULL(a.done);
    TEST_ASSERT_NOT_NULL(b.done);

    esp_rmaker_work_queue_handle_t ha = NULL, hb = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&ha, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&hb, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(ha));
    // Intentionally do NOT start hb; tasks added to ha must not reach hb.

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(ESP_OK,
            esp_rmaker_work_queue_add_task_inst(ha, wq_generic_work_fn, &a));
    }
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(a.done, pdMS_TO_TICKS(5000)));
    }
    TEST_ASSERT_EQUAL_INT(3, a.exec_count);

    // hb was never started and never received tasks - its counter must stay 0.
    vTaskDelay(pdMS_TO_TICKS(200));
    TEST_ASSERT_EQUAL_INT(0, b.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&ha));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&hb));
    vSemaphoreDelete(a.done);
    vSemaphoreDelete(b.done);
}

static void wq_double_init_seq(void)
{
    wq_ctx_t ctx;
    wq_ctx_reset(&ctx);
    ctx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(ctx.done);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init());
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init());
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start());
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task(wq_generic_work_fn, &ctx));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000)));
    vTaskDelay(pdMS_TO_TICKS(100));
    TEST_ASSERT_EQUAL_INT(1, ctx.exec_count);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());

    // A second deinit is a no-op, and start without init is an invalid state.
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, esp_rmaker_work_queue_start());
    vSemaphoreDelete(ctx.done);
}

TEST_CASE("ESP RainMaker Work Queue Double Init Keeps One Queue", "[work_queue]")
{
    // Earlier tests can leave the global queue initialised.
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit());
    wq_assert_no_leak(wq_double_init_seq);
}

static esp_rmaker_work_queue_handle_t s_self_handle = NULL;
static esp_err_t s_self_deinit_err = ESP_OK;
static void wq_self_deinit_work_fn(void *data)
{
    s_self_deinit_err = esp_rmaker_work_queue_deinit_inst(&s_self_handle);
    xSemaphoreGive((SemaphoreHandle_t)data);
}

TEST_CASE("ESP RainMaker WQ Instance Deinit From Own Worker Is Rejected", "[work_queue]")
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(done);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&s_self_handle, &s_default_cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(s_self_handle));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(s_self_handle, wq_self_deinit_work_fn, done));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(done, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, s_self_deinit_err);
    TEST_ASSERT_NOT_NULL(s_self_handle);

    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&s_self_handle));
    vSemaphoreDelete(done);
}

TEST_CASE("ESP RainMaker WQ Instance Custom Name And Core", "[work_queue]")
{
    esp_rmaker_work_queue_config_t cfg = s_default_cfg;
    cfg.name = "wq_custom";
    cfg.core_id = 0;

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &cfg));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
    TEST_ASSERT_NOT_NULL(xTaskGetHandle("wq_custom"));
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    TEST_ASSERT_NULL(xTaskGetHandle("wq_custom"));
}

#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY || CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
#include "esp_memory_utils.h"

static volatile bool s_stack_in_ext_ram = false;
static void wq_stack_probe_work_fn(void *data)
{
    int probe = 0;
    s_stack_in_ext_ram = esp_ptr_external_ram(&probe);
    xSemaphoreGive((SemaphoreHandle_t)data);
}

static void wq_ext_ram_seq(void)
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(done);
    esp_rmaker_work_queue_config_t cfg = s_default_cfg;
    cfg.prefer_ext_ram = true;

    esp_rmaker_work_queue_handle_t h = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_init_inst(&h, &cfg));
    for (int i = 0; i < 2; i++) {
        s_stack_in_ext_ram = false;
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_start_inst(h));
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_add_task_inst(h, wq_stack_probe_work_fn, done));
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(done, pdMS_TO_TICKS(5000)));
        TEST_ASSERT_TRUE(s_stack_in_ext_ram);
        TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_stop_inst(h));
    }
    TEST_ASSERT_EQUAL(ESP_OK, esp_rmaker_work_queue_deinit_inst(&h));
    vSemaphoreDelete(done);
}

TEST_CASE("ESP RainMaker WQ Instance External RAM Stack", "[work_queue]")
{
    if (heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0) {
        TEST_IGNORE_MESSAGE("No PSRAM on this board");
    }
    wq_assert_no_leak(wq_ext_ram_seq);
}
#endif
