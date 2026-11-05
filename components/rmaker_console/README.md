# rmaker_console

[![Component Registry](https://components.espressif.com/components/espressif/rmaker_console/badge.svg)](https://components.espressif.com/components/espressif/rmaker_console)

Serial console integration for ESP RainMaker: initializes the console and registers common RainMaker CLI commands.

## Overview

Call `esp_rmaker_common_console_init()` for a one-shot setup, or initialize the console yourself and then call `esp_rmaker_common_register_commands()` to add the shared RainMaker commands only.

## Requirements

- ESP-IDF v5.1 or newer
- The Linux target needs ESP-IDF v5.5 or newer

## Configuration

- `CONFIG_ESP_RMAKER_CONSOLE_USE_REPL` uses the `esp_console` REPL, with line editing and command history. It adds about 14 KB of flash. It is always on for the Linux target and off by default on chip targets, which use a smaller UART console task.
- `CONFIG_ESP_RMAKER_CONSOLE_MAX_HISTORY_LEN` sets the number of commands in the REPL history.

With `CONFIG_ESP_RMAKER_CONSOLE_USE_REPL`:
- `esp_rmaker_common_console_init()` calls `esp_console_init()`. Do not call `esp_console_init()` before it. On ESP-IDF v6.1 and later, a failed REPL start also deinitializes `esp_console`.
- The REPL cuts a line that is too long to 245 characters, then runs it. The legacy task discards the line. The ESP-IDF REPL task runs each line itself, so this component cannot discard it.

## Dependencies

- `espressif/rmaker_system_ctrl`
- `espressif/rmaker_time_sync`

See `esp_rmaker_common_console.h` for initialization notes and extension points.
