/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "unity.h"
#include "rmaker_console_line_edit.h"

/* Assemble a line from raw input as the UART reader task does; return true at CR or LF. */
static bool assemble_line(const char *input, size_t input_len, char *out, size_t out_size)
{
    rmaker_console_esc_state_t esc_state = RMAKER_CONSOLE_ESC_NONE;
    size_t i = 0;
    bool eol = false;

    for (size_t n = 0; n < input_len && i < out_size - 1; n++) {
        uint8_t c = (uint8_t) input[n];
        rmaker_console_byte_action_t action = rmaker_console_classify_byte(c, &esc_state);
        if (action == RMAKER_CONSOLE_BYTE_IGNORE) {
            continue;
        } else if (action == RMAKER_CONSOLE_BYTE_BACKSPACE) {
            if (i > 0) {
                i--;
            }
        } else if (action == RMAKER_CONSOLE_BYTE_EOL) {
            eol = true;
            break;
        } else { /* RMAKER_CONSOLE_BYTE_STORE */
            out[i++] = (char) c;
        }
    }
    out[i] = '\0';
    return eol;
}

TEST_CASE("console: plain input is stored verbatim", "[rmaker_console]")
{
    char line[64];
    bool eol = assemble_line("hello\r", 6, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("hello", line);
}

TEST_CASE("console: up arrow is ignored", "[rmaker_console]")
{
    /* ESC [ A == up arrow, embedded mid-line */
    const char in[] = "ab\x1b[Acd\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("abcd", line);
}

TEST_CASE("console: all four arrow keys are ignored", "[rmaker_console]")
{
    /* up, down, right, left */
    const char in[] = "\x1b[A\x1b[B\x1b[C\x1b[Dxyz\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("xyz", line);
}

TEST_CASE("console: multi-param and SS3 sequences are ignored", "[rmaker_console]")
{
    /* ESC [ 3 ~ == Delete, ESC O H == Home (SS3) */
    const char in[] = "a\x1b[3~b\x1bOHc\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("abc", line);
}

TEST_CASE("console: backspace erases last char only", "[rmaker_console]")
{
    char line[64];
    bool eol = assemble_line("abc\b\bX\r", 7, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("aX", line);
}

TEST_CASE("console: backspace on empty line is a no-op", "[rmaker_console]")
{
    char line[64];
    bool eol = assemble_line("\b\bok\r", 5, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("ok", line);
}

TEST_CASE("console: lone ESC does not swallow following text", "[rmaker_console]")
{
    /* ESC not followed by '[' or 'O': filter resets, next bytes are normal. */
    const char in[] = "a\x1b" "bc\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("abc", line);
}

TEST_CASE("console: line of only escape sequences is empty, no underflow", "[rmaker_console]")
{
    const char in[] = "\x1b[A\x1b[B\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("", line);
}

TEST_CASE("console: escape state persists across reads (split sequence)", "[rmaker_console]")
{
    /* The reader may receive an escape sequence split across UART reads; the
     * esc_state is carried across calls, so a split sequence is still filtered. */
    rmaker_console_esc_state_t esc_state = RMAKER_CONSOLE_ESC_NONE;
    char buf[16];
    size_t i = 0;

    const char *chunk1 = "x\x1b";   /* sequence starts here */
    const char *chunk2 = "[Ay";     /* and finishes in the next read */

    for (const char *p = chunk1; *p; p++) {
        if (rmaker_console_classify_byte((uint8_t) *p, &esc_state) == RMAKER_CONSOLE_BYTE_STORE) {
            buf[i++] = *p;
        }
    }
    for (const char *p = chunk2; *p; p++) {
        if (rmaker_console_classify_byte((uint8_t) *p, &esc_state) == RMAKER_CONSOLE_BYTE_STORE) {
            buf[i++] = *p;
        }
    }
    buf[i] = '\0';
    TEST_ASSERT_EQUAL_STRING("xy", buf);
}

TEST_CASE("console: LF ends the line", "[rmaker_console]")
{
    char line[64];
    bool eol = assemble_line("hi\n", 3, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("hi", line);
}

TEST_CASE("console: CR ends an incomplete escape sequence", "[rmaker_console]")
{
    rmaker_console_esc_state_t esc_state = RMAKER_CONSOLE_ESC_NONE;
    const char in[] = "\x1b[";

    for (size_t n = 0; n < sizeof(in) - 1; n++) {
        TEST_ASSERT_EQUAL(RMAKER_CONSOLE_BYTE_IGNORE, rmaker_console_classify_byte((uint8_t) in[n], &esc_state));
    }
    TEST_ASSERT_EQUAL(RMAKER_CONSOLE_BYTE_EOL, rmaker_console_classify_byte('\r', &esc_state));
    TEST_ASSERT_EQUAL(RMAKER_CONSOLE_ESC_NONE, esc_state);
    TEST_ASSERT_EQUAL(RMAKER_CONSOLE_BYTE_STORE, rmaker_console_classify_byte('a', &esc_state));
}

TEST_CASE("console: DEL erases the last char", "[rmaker_console]")
{
    char line[64];
    bool eol = assemble_line("abc\x7f\x7fX\r", 7, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("aX", line);
}

TEST_CASE("console: other control bytes are ignored", "[rmaker_console]")
{
    /* NUL, BEL, TAB, FF */
    const char in[] = "a\x00" "b\x07" "c\td\x0c" "e\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("abcde", line);
}

TEST_CASE("console: UTF-8 bytes are stored", "[rmaker_console]")
{
    const char in[] = "caf\xc3\xa9\r";
    char line[64];
    bool eol = assemble_line(in, sizeof(in) - 1, line, sizeof(line));
    TEST_ASSERT_TRUE(eol);
    TEST_ASSERT_EQUAL_STRING("caf\xc3\xa9", line);
}
