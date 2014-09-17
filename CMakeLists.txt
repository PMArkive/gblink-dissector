#
# Copyright (c) 2014 Nicholas Corgan (n.corgan@gmail.com)
#
# Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
# or copy at http://opensource.org/licenses/MIT)
#
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(nintendo-dissectors C)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

FIND_PACKAGE(Wireshark REQUIRED)
FIND_PACKAGE(GLIB2 REQUIRED)

ADD_SUBDIRECTORY(gblink-dissector)
