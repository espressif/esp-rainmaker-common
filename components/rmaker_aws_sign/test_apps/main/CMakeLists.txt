set(srcs
    "test_app_main.c"
    "test_aws_sign_common.c"
    "test_aws_sign_crypto.c"
    "test_aws_sign_sigv4.c"
    "test_aws_sign_json.c"
    "test_aws_sign_creds.c"
    "test_aws_sign_http.c"
    "test_aws_sign_port.c")

# The tests drive the pure helpers in the component's private header.
idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS "."
                       PRIV_INCLUDE_DIRS "../../priv_include"
                       PRIV_REQUIRES unity lwip esp_netif esp_event
                       WHOLE_ARCHIVE)
