# rmaker_work_queue

[![Component Registry](https://components.espressif.com/components/espressif/rmaker_work_queue/badge.svg)](https://components.espressif.com/components/espressif/rmaker_work_queue)

Dedicated-thread work queue for ESP RainMaker: queue callbacks to run sequentially on a single worker task. Supports a single process-wide **global** queue and any number of independent queue **instances**.

## Overview

Each queue owns one worker task that dequeues callbacks and runs them in FIFO order. Work functions execute in the worker's task context (not ISR-safe unless your callback handles that).

Two flavors:

- **Global queue** — one shared instance per process. Configured via sdkconfig; simpler API.
- **Queue instance** — separate from the global queue, with its own worker task. Caller-owned handle, per-instance `esp_rmaker_work_queue_config_t`. Use to isolate workloads, pick a different stack/priority, or run queues in parallel.

## Requirements

- ESP-IDF v5.1 or newer

## Global queue flow

```c
#include <esp_rmaker_work_queue.h>

static void my_work(void *priv) { /* ... */ }

esp_rmaker_work_queue_init();
esp_rmaker_work_queue_start();

esp_rmaker_work_queue_add_task(my_work, priv_data);

/* shutdown */
esp_rmaker_work_queue_stop();
esp_rmaker_work_queue_deinit();
```

Sizing is driven by Kconfig (`CONFIG_ESP_RMAKER_WORK_QUEUE_SIZE`, `_TASK_STACK`, `_TASK_PRIORITY`, `_PREFER_EXT_RAM`).

## Queue instance flow

```c
#include <esp_rmaker_work_queue.h>

esp_rmaker_work_queue_handle_t h = NULL;
esp_rmaker_work_queue_config_t cfg = ESP_RMAKER_WORK_QUEUE_CONFIG_DEFAULT();
cfg.stack_size = 8192;           /* override as needed */
cfg.priority = 6;
cfg.name = "my_wq";

esp_rmaker_work_queue_init_inst(&h, &cfg);   /* h must be NULL */
esp_rmaker_work_queue_start_inst(h);

esp_rmaker_work_queue_add_task_inst(h, my_work, priv_data);

/* shutdown */
esp_rmaker_work_queue_stop_inst(h);
esp_rmaker_work_queue_deinit_inst(&h);   /* sets h to NULL on success */
```

Multiple queue instances can coexist with each other and with the global queue; each runs on its own worker task.

### Configuration fields

| Field            | Notes                                                                 |
|------------------|-----------------------------------------------------------------------|
| `size`           | Max pending entries. Must be > 0. `add_task_inst` returns `ESP_FAIL` when full. |
| `stack_size`     | Worker task stack in **bytes**. Must be > 0.                          |
| `priority`       | FreeRTOS priority of the worker task, from 1 to `configMAX_PRIORITIES - 1`. Priority 0 (idle) is rejected. |
| `name`           | Worker task name, copied at init. `NULL` gives `rmaker_wq-<n>`. FreeRTOS keeps only the first `configMAX_TASK_NAME_LEN - 1` characters. |
| `core_id`        | Core to pin the worker task to, or `tskNO_AFFINITY`.                  |
| `prefer_ext_ram` | If true, stack is allocated from SPIRAM with internal-RAM fallback; TCB always in internal RAM. **Only enable if no work fn on this queue writes flash/NVS** — a SPIRAM stack faults when the cache is disabled (flash/NVS write). Requires `CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM` (IDF v5.4 and newer) or `CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY` (IDF v5.3 and older). If the option is disabled, the flag is ignored at runtime (internal RAM, with a warning). Default off; leave off for the global queue (it writes NVS). |

Always start from `ESP_RMAKER_WORK_QUEUE_CONFIG_DEFAULT()`, then override only the fields you need. New fields then get their defaults.

### Memory cost per queue instance

Each queue instance is a full FreeRTOS task. Approximate cost on a 32-bit target:

- 52 B control block (external RAM if available)
- `size × 8` B of queue storage, plus about 80 B of queue overhead (internal RAM)
- About 350 B TCB (internal RAM)
- The stack, `stack_size` bytes

The stack and TCB stay allocated after `stop*`. Only `deinit*` frees them. This also applies to the global queue.

## Semantics

- `add_task*` is non-blocking (zero-timeout enqueue). Returns `ESP_FAIL` if the queue is full, and `ESP_ERR_INVALID_ARG` if `work_fn` is `NULL`.
- Tasks are executed in FIFO order by a single worker per queue.
- Tasks enqueued before `start` are buffered and drained once the worker starts.
- `stop*` is asynchronous. It wakes the worker, and the worker parks after it runs **all entries that are in the queue**. This usually takes milliseconds, plus the run time of those entries.
- Entries added after the worker parks stay in the queue. They run on the next `start*`, or `deinit*` drops them.
- `stop*` does not free the worker stack or TCB. Call `deinit*` to free them.
- `start*` after `stop*` resumes the same worker task. If the worker has not parked yet, `start*` waits for it.
- `deinit*` blocks until the worker has parked, then deletes the task and queue. You can call it without a prior `stop*`. A second `deinit*` is a no-op.
- Do not call `deinit*` (or `start*` after `stop*`) from a work function of the same queue. It returns `ESP_ERR_INVALID_STATE`.
- The global `esp_rmaker_work_queue_init()` is safe to call more than once. Later calls return `ESP_OK` and use the same queue.

## Dependencies

- None beyond ESP-IDF (FreeRTOS, heap caps).
- The queue instance API needs `rmaker_work_queue` v1.1.0 or newer. If you use it, add `espressif/rmaker_work_queue: "^1.1.0"` to your own `idf_component.yml`. Do not rely on the version that `rmaker_common` pulls in.

See `include/esp_rmaker_work_queue.h` for full API reference.
