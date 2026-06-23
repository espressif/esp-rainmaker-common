/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Action to take for a received console input byte.
 *
 * Result of classifying a single byte from the raw input stream of the
 * legacy UART console line reader.
 */
typedef enum {
    RMAKER_CONSOLE_BYTE_IGNORE = 0, /*!< Escape sequence byte or other control byte; drop it. */
    RMAKER_CONSOLE_BYTE_STORE,      /*!< Byte to append to the line buffer. */
    RMAKER_CONSOLE_BYTE_BACKSPACE,  /*!< Backspace or DEL; erase the last stored byte. */
    RMAKER_CONSOLE_BYTE_EOL,        /*!< CR or LF; the line is complete. */
} rmaker_console_byte_action_t;

/**
 * @brief Escape-sequence filter state, carried across bytes of a line.
 * @note Set it to RMAKER_CONSOLE_ESC_NONE before the first byte of each line.
 */
typedef enum {
    RMAKER_CONSOLE_ESC_NONE = 0, /*!< Normal: no escape sequence in progress. */
    RMAKER_CONSOLE_ESC_SEEN,     /*!< ESC received; awaiting introducer. */
    RMAKER_CONSOLE_ESC_SEQ,      /*!< Inside CSI/SS3; consuming until final byte. */
} rmaker_console_esc_state_t;

/**
 * @brief Classify one received byte; drop escape sequences (arrow keys) and other control bytes.
 *
 * @param[in]     c          The received byte.
 * @param[in,out] esc_state  Filter state, carried across calls.
 *
 * @return The action the caller should take for this byte.
 */
rmaker_console_byte_action_t rmaker_console_classify_byte(uint8_t c, rmaker_console_esc_state_t *esc_state);

#ifdef __cplusplus
}
#endif
