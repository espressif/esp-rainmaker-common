# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import subprocess
import time

import pexpect
import pytest
from pytest_embedded_idf.app import IdfApp
from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.utils import idf_parametrize

# Linux always uses the REPL. A chip uses the legacy UART task unless sdkconfig.ci.repl is applied.
TARGETS = ['linux', 'esp32c3']

COMMAND_FAILED = {
    'repl': "Command returned non-zero error code",
    'legacy': "Console command failed with error",
}


def reset_chip(dut: IdfDut):
    """Reset the chip without esptool, with the DTR/RTS pulse of test_app/run_test.py"""
    time.sleep(0.1)
    dut.serial.proc.dtr = False
    dut.serial.proc.rts = False
    time.sleep(0.5)
    dut.serial.proc.dtr = True
    dut.serial.proc.rts = True
    time.sleep(0.1)


def wait_ready(dut: IdfDut, target: str) -> str:
    """Reset a chip, wait for the console and return its type: "repl" or "legacy" """
    if target != 'linux':
        reset_chip(dut)
    match = dut.expect(r"rmaker_console_test: ready \((repl|legacy)\)")
    return match.group(1).decode()


def run_command(dut: IdfDut, target: str, command: str) -> str:
    """Wait for the console, send one command line and return the console type"""
    console = wait_ready(dut, target)
    dut.write(command)
    return console


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_help(dut: IdfDut, target: str):
    """help lists the RainMaker common commands"""
    run_command(dut, target, "help")
    # help prints the commands in registration order.
    for command in ("up-time", "mem-dump", "task-dump", "reset-to-factory", "local-time", "tz-set"):
        dut.expect_exact(command)


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_up_time(dut: IdfDut, target: str):
    """up-time prints the uptime in milliseconds"""
    run_command(dut, target, "up-time")
    dut.expect(r"Uptime of the device: \d+ milliseconds")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_tz_set_posix(dut: IdfDut, target: str):
    """tz-set posix changes the time zone that local-time uses"""
    run_command(dut, target, "tz-set posix CST-8")
    dut.write("local-time")
    dut.expect(r"Current local time: .*\+0800\[CST\]")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_tz_set_no_args(dut: IdfDut, target: str):
    """tz-set without a time zone returns an error"""
    console = run_command(dut, target, "tz-set")
    dut.expect_exact("Invalid Usage.")
    dut.expect_exact(COMMAND_FAILED[console])


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_unknown_command(dut: IdfDut, target: str):
    """An unknown command is rejected, and the console accepts the next command"""
    console = run_command(dut, target, "no-such-command")
    if console == 'repl':
        dut.expect_exact("Unrecognized command")
    dut.write("up-time")
    dut.expect(r"Uptime of the device: \d+ milliseconds")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_console_idle_without_prompt_loop(dut: IdfDut, target: str):
    """The console waits for input and does not print the prompt again (esp-idf#15056)"""
    wait_ready(dut, target)
    with pytest.raises(pexpect.TIMEOUT):
        dut.expect(r">> [\s\S]*>> ", timeout=1.5)


@idf_parametrize('target', ['linux'], indirect=['target'])
def test_console_stdin_closed(app: IdfApp):
    """A closed stdin stops the console input and does not print the prompt in a loop"""
    proc = subprocess.Popen([app.elf_file], cwd=app.app_path, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        out, _ = proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    text = out.decode(errors='replace')
    assert "stdin closed; console input stopped" in text
    assert text.count(">> ") <= 1, f"{text.count('>> ')} prompts with stdin closed"
