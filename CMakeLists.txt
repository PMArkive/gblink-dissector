#
# Copyright (c) 2014 Nicholas Corgan (n.corgan@gmail.com)
#
# Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
# or copy at http://opensource.org/licenses/MIT)
#
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(gblink-dissector C)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

FIND_PACKAGE(Wireshark REQUIRED)
FIND_PACKAGE(GLIB2 REQUIRED)
FIND_PACKAGE(PythonInterp REQUIRED)

INCLUDE_DIRECTORIES(
    ${GLIB2_INCLUDE_DIRS}
    ${WIRESHARK_INCLUDE_DIRS}
)

SET(PLUGIN_GENERATOR ${CMAKE_SOURCE_DIR}/make-dissector-reg.py)

MACRO(BUILD_WIRESHARK_PLUGIN plugin)
    INCLUDE_DIRECTORIES(
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    SET(PACKET_PLUGIN_C "${CMAKE_CURRENT_SOURCE_DIR}/packet-${plugin}.c")
    SET(PLUGIN_PLUGIN_C "${CMAKE_CURRENT_BINARY_DIR}/${plugin}-plugin.c")

    ADD_CUSTOM_COMMAND(
        COMMAND ${PYTHON_EXECUTABLE} ${PLUGIN_GENERATOR} ${CMAKE_CURRENT_SOURCE_DIR} plugin ${PLUGIN_PLUGIN_C} ${PACKET_PLUGIN_C}
        DEPENDS ${PACKET_PLUGIN_C}
        OUTPUT ${PLUGIN_PLUGIN_C}
        COMMENT "Generating ${plugin}-plugin.c"
    )

    ADD_LIBRARY(${plugin}-plugin MODULE
        ${PACKET_PLUGIN_C}
        ${PLUGIN_PLUGIN_C}
        ${CMAKE_CURRENT_SOURCE_DIR}/moduleinfo.h
    )

    ADD_DEPENDENCIES(${plugin}-plugin ${PLUGIN_PLUGIN_C})
    SET_TARGET_PROPERTIES(${plugin}-plugin PROPERTIES PREFIX "")
    SET_TARGET_PROPERTIES(${plugin}-plugin PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
    TARGET_LINK_LIBRARIES(${plugin}-plugin ${WIRESHARK_LIBRARIES} ${GLIB2_LIBRARIES})
ENDMACRO(BUILD_WIRESHARK_PLUGIN)

MESSAGE(STATUS "") #Formatting
ADD_SUBDIRECTORY(gblink-dissector)
