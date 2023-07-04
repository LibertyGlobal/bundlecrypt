
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2023 Liberty Global B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Damian Wrobel <dwrobel@ertelnet.rybnik.pl>
#

cmake_minimum_required(VERSION 3.10)
project(dmcrypt-rdk VERSION 1.8 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(VERSION "Software version string e.g. 1.8 (default: none)" OFF)
option(RELEASE "Package release number e.g. 1 (default: none)" OFF)

if (VERSION)
  set(CPACK_DEBIAN_PACKAGE_VERSION ${VERSION})
  add_definitions(-DVERSION=\"${VERSION}\")
endif()

if (RELEASE)
  set(CPACK_DEBIAN_PACKAGE_RELEASE ${RELEASE})
  set(CPACK_RPM_PACKAGE_RELEASE ${RELEASE})
endif()

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "onemw_infrastructure@libertyglobal.com")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "coreutils, cryptsetup, libcap2-bin")
set(CPACK_DEBIAN_PACKAGE_CONFLICTS "onemw-encrypt-image")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_BINARY_DIR}/postinst")

set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_REQUIRES "coreutils cryptsetup")
set(CPACK_RPM_PACKAGE_RELEASE_DIST "%{?dist}")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/sbin")
set(CPACK_RPM_USER_FILELIST "%caps(cap_setuid+ep) /usr/sbin/dmcrypt-rdk")

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "cryptsetup wrapper tool")

configure_file(postinst.in postinst @ONLY)

add_executable(${PROJECT_NAME} ${PROJECT_NAME}.c)

target_compile_options(${PROJECT_NAME}
  PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter
)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

execute_process(
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ../${CMAKE_INSTALL_SBINDIR}/${PROJECT_NAME}
    ${CMAKE_BINARY_DIR}/onemw-encrypt-image
)

install(FILES ${CMAKE_BINARY_DIR}/onemw-encrypt-image
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

include(CPack)
