include(${CMAKE_CURRENT_LIST_DIR}/rmaker_aws_sign_variables.cmake)

# The ESP-IDF port. esp_rmaker_aws_sign_default.c is what binds it to
# esp_rmaker_aws_sign_port_install_default(); the port/esp sources are reachable only from there.
#
# CONFIG_ESP_RMAKER_AWS_SIGN_DISABLE_DEFAULT_PORT=y drops them from the build
# outright. That is a stronger guarantee than the link-time one: with the default
# port compiled in, an application that only calls
# esp_rmaker_aws_sign_port_install() still gets it stripped, but the objects
# are built either way.
if(NOT CONFIG_ESP_RMAKER_AWS_SIGN_DISABLE_DEFAULT_PORT)
    list(APPEND RMAKER_AWS_SIGN_SRCS "src/esp_rmaker_aws_sign_default.c"
                                     "port/esp/crypto.c"
                                     "port/esp/http.c"
                                     "port/esp/json.c"
                                     "port/esp/log.c"
                                     "port/esp/mem.c"
                                     "port/esp/mutex.c"
                                     "port/esp/time.c")
endif()

# Declared unconditionally, unlike the sources above. ESP-IDF resolves component
# requirements in an early expansion pass that runs before the configuration
# exists, so a CONFIG_-guarded PRIV_REQUIRES is silently ignored and the port
# sources fail to find their headers. Requiring these always is harmless: with
# the default port disabled nothing references them, so nothing is linked.
list(APPEND RMAKER_AWS_SIGN_PRIV_REQUIRES "esp_http_client" "esp-tls" "mbedtls")

# cJSON moved out of ESP-IDF to the component manager in IDF v6.0.
if("${IDF_VERSION_MAJOR}" LESS 6)
    list(APPEND RMAKER_AWS_SIGN_PRIV_REQUIRES "json")
else()
    list(APPEND RMAKER_AWS_SIGN_PRIV_REQUIRES "cjson")
endif()

# Nothing in REQUIRES: the public header declares only function-pointer types,
# esp_err_t and libc types, so a consumer of it pulls in no transitive dependency.
idf_component_register(SRCS ${RMAKER_AWS_SIGN_SRCS}
                       INCLUDE_DIRS ${RMAKER_AWS_SIGN_INCLUDE_DIRS}
                       PRIV_INCLUDE_DIRS ${RMAKER_AWS_SIGN_PRIV_INCLUDE_DIRS}
                       PRIV_REQUIRES ${RMAKER_AWS_SIGN_PRIV_REQUIRES})
