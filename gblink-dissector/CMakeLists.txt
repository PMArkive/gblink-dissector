#
# Copyright (c) 2014 Nicholas Corgan (n.corgan@gmail.com)
#
# Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
# or copy at http://opensource.org/licenses/MIT)
#

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${GLIB2_INCLUDE_DIRS}
    ${WIRESHARK_INCLUDE_DIRS}
)

SET(GBLINK_PLUGIN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/packet-gblink.c)
SET(GBPLUGIN_C_GENERATOR ${CMAKE_SOURCE_DIR}/make-dissector-reg.py)
SET(GBPLUGIN_C gblink-plugin.c)

ADD_CUSTOM_COMMAND(
    OUTPUT ${GBPLUGIN_C}
    DEPENDS ${GBLINK_PLUGIN_SRC}
    COMMAND ${GBPLUGIN_C_GENERATOR} ${CMAKE_CURRENT_SOURCE_DIR} plugin gblink-plugin.c ${GBLINK_PLUGIN_SRC}
    COMMENT "Generating ${GBPLUGIN_C}"
)

ADD_LIBRARY(gblink-plugin MODULE
    ${GBPLUGIN_C}
    moduleinfo.h
    ${GBLINK_PLUGIN_SRC}
)

SET_TARGET_PROPERTIES(gblink-plugin PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES(gblink-plugin PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
TARGET_LINK_LIBRARIES(gblink-plugin wireshark)
