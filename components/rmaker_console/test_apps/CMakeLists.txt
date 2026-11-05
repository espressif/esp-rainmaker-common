cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Include only main and what it depends on.
set(COMPONENTS main)

project(rmaker_console_test)
