# RainMaker Common Unit Tests

This directory contains unit tests for the RainMaker Common component.

## Prerequisites

- ESP-IDF (v4.4 or newer)
- An ESP32 development board

## Building and Running the Tests

```bash
idf.py build
idf.py -p [PORT] flash monitor
```

## Test Components

The tests cover the following functionalities:

1. **Utility Functions**
   - Time synchronization
   - Timezone management
   - System reboot and reset operations

2. **Work Queue**
   - Task initialization
   - Task scheduling
   - Delayed task execution
   - Task prioritization

## Known Issues

1. Some tests require network connectivity for time synchronization.
2. The linter errors related to header files are expected during development as the test project needs to be built with ESP-IDF to resolve includes.
3. The reboot and reset tests use large delays to avoid actually rebooting the device during tests.

## Resolving Include Path Issues

If you're facing linter errors related to missing include paths, you can:

1. Build the project once using `idf.py build`
2. Point your editor to use the compile_commands.json generated in the build directory
3. For VS Code, add this to .vscode/c_cpp_properties.json:

```json
{
    "compileCommands": "${workspaceFolder}/components/rmaker_common/test_apps/build/compile_commands.json"
}
```
