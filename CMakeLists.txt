set(srcs "src/work_queue.c" "src/factory.c" "src/time.c" "src/timezone.c" "src/utils.c" "src/create_APN3_PPI_string.c" "src/cmd_resp.c")
set(priv_req "mqtt" "nvs_flash")

# from IDF version 5.0, we need to explicitly specify requirements
if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER_EQUAL "5.0")
    list(APPEND priv_req esp_wifi)
    set(requires esp_event)
endif()
#if(CONFIG_ESP_RMAKER_LIB_ESP_MQTT)
    list(APPEND srcs "src/esp-mqtt/esp-mqtt-glue.c")
#endif()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS
                       REQUIRES ${requires}
                       PRIV_REQUIRES ${priv_req})
