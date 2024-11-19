#=======================================
#SEAL SQ 2024
#Zero Touch Provisioning Demo with INeS
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

# Nous voulons un cmake "récent" pour utiliser les dernières fonctionnalités
cmake_minimum_required(VERSION 3.6)

#Project name
project(zeroTouchProvisioning_app VERSION 1.0.0)
add_subdirectory(lib/ines_sdk_c)

#VAULTIC LIB

if(${COMPILATION_MODE} STREQUAL "DEBUG")
add_compile_definitions(INES_SDK_DEBUG)
endif()



include_directories(include)

#VAULTIC LIB
set(HEADERS
    "include/aws_demo.h"
)

#source files directory
set(SRCS 

    "src/aws_demo.c"
    "src/main.c"
    )

set(MQTT_SRCS 
    "lib/wolfMQTT/examples/mqttexample.c"
    "lib/wolfMQTT/examples/mqttnet.c"
    )

# setup wolfMQTT options
set(WOLFMQTT_EXAMPLES "OFF" CACHE BOOL "" FORCE)
add_compile_definitions(ENABLE_MQTT_TLS=YES)
add_subdirectory(lib/wolfMQTT)

add_executable(zeroTouchProvisioning_app ${SRCS} ${HEADERS} ${MQTT_SRCS})
target_link_libraries(zeroTouchProvisioning_app ines_SDK_lib wolfssl wolfmqtt)
target_include_directories(zeroTouchProvisioning_app PUBLIC lib/ines_sdk_c/include)
target_link_directories(zeroTouchProvisioning_app PUBLIC lib/ines_sdk_c/include)
