# Platform-independent half of the rmaker_aws_sign component.
#
# Everything listed here reaches the outside world only through the function
# pointers in include/esp_rmaker_aws_sign.h - including SHA-256 and HMAC - so it
# builds anywhere libc is available. Include this file and append your own port
# sources to build against a platform other than ESP-IDF; see CMakeLists.txt for
# how the ESP-IDF port does exactly that.
#
# Note that src/esp_rmaker_aws_sign_default.c is deliberately NOT listed here. It
# is the only referrer of the ESP-IDF port tables, and keeping it in a separate
# object is what lets the linker drop the default port for anyone who calls
# esp_rmaker_aws_sign_port_install() instead of esp_rmaker_aws_sign_port_install_default().

# Source files
set(RMAKER_AWS_SIGN_SRCS "${CMAKE_CURRENT_LIST_DIR}/src/esp_rmaker_aws_sign_accum.c"
                         "${CMAKE_CURRENT_LIST_DIR}/src/esp_rmaker_aws_sign_sigv4.c"
                         "${CMAKE_CURRENT_LIST_DIR}/src/esp_rmaker_aws_sign_creds.c"
                         "${CMAKE_CURRENT_LIST_DIR}/src/esp_rmaker_aws_sign_send_request.c"
                         "${CMAKE_CURRENT_LIST_DIR}/src/esp_rmaker_aws_sign_port.c")

# Include directories
set(RMAKER_AWS_SIGN_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/include")

# Private include directories
set(RMAKER_AWS_SIGN_PRIV_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/priv_include")

# Private requirements: empty, and that is the point. Crypto is behind the port
# and the one JSON document this component reads has a purpose-built scanner, so
# the platform-independent half needs no crypto library, no TLS stack, no JSON
# library and no RTOS - just libc.
set(RMAKER_AWS_SIGN_PRIV_REQUIRES)
