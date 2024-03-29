#
# Esras: OAuth2/OIDC client program manager
#
# CMake file used to build program
#
# Copyright 2022 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the MIT License
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

cmake_minimum_required(VERSION 3.5)

project(esras C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wconversion")

# library info

set(PROGRAM_VERSION_MAJOR "0")
set(PROGRAM_VERSION_MINOR "9")
set(PROGRAM_VERSION_PATCH "9")
set(PROJECT_DESCRIPTION "OAuth2/OIDC client program manager")
set(JANSSON_VERSION_REQUIRED "2.11")
set(ORCANIA_VERSION_REQUIRED "2.3.3")
set(YDER_VERSION_REQUIRED "1.4.19")
set(ULFIUS_VERSION_REQUIRED "2.7.14")
set(HOEL_VERSION_REQUIRED "1.4.27")
set(RHONABWY_VERSION_REQUIRED "1.1.12")
set(IDDAWC_VERSION_REQUIRED "1.1.8")

include(GNUInstallDirs)
include(CheckSymbolExists)

# cmake modules

set(E_CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)
list(APPEND CMAKE_MODULE_PATH "${E_CMAKE_MODULE_PATH}")

# check if _GNU_SOURCE is available

if (NOT _GNU_SOURCE)
    check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

    if (NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        check_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif ()
endif ()

if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
  set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})
  include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()

include(FindJansson)
set(JANSSON_MIN_VERSION 2.4)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
if (JANSSON_FOUND)
    set(LIBS ${LIBS} ${JANSSON_LIBRARIES})
endif ()

include(FindLibconfig)
find_package(Libconfig REQUIRED)
if (LIBCONFIG_FOUND)
    set(LIBS ${LIBS} ${LIBCONFIG_LIBRARIES})
    include_directories(${LIBCONFIG_INCLUDE_DIRS})
endif ()

include(FindZLIB)
find_package(ZLIB REQUIRED)
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# build

add_executable(esras ${CMAKE_CURRENT_SOURCE_DIR}/src/esras.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/static_compressed_inmemory_website_callback.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/http_compression_callback.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/static_compressed_inmemory_website_callback.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/http_compression_callback.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/exec.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/esras.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/webservice.c
                     ${CMAKE_CURRENT_SOURCE_DIR}/src/session.c )
target_link_libraries(esras ${LIBS})
set_target_properties(esras PROPERTIES COMPILE_OPTIONS "-Wextra;-Wconversion")

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during orcania search and download
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download

set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during ulfius search and download
set(BUILD_UWSC OFF CACHE BOOL "Force to false") # Avoid to build uwsc during ulfius search and download

set(SEARCH_ORCANIA_H OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during hoel search and download

set(SEARCH_ORCANIA_R OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during hoel search and download
set(SEARCH_YDER_R OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download
set(SEARCH_ULFIUS_R OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during rhonabwy search and download

set(SEARCH_ORCANIA_I OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during iddawc search and download
set(SEARCH_YDER_I OFF CACHE BOOL "Force to false") # Avoid to search and download yder during iddawc search and download
set(SEARCH_ULFIUS_I OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during iddawc search and download
set(SEARCH_RHONABWY_I OFF CACHE BOOL "Force to false") # Avoid to search and download rhonabwy during iddawc search and download

option(DOWNLOAD_DEPENDENCIES "Download required dependencies" ON)

set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
include(FindOrcania)
find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
if (ORCANIA_FOUND)
    if ("${ORCANIA_VERSION_STRING}" VERSION_GREATER_EQUAL "${ORCANIA_VERSION_REQUIRED}")
        message(STATUS "Orcania found: ${ORCANIA_VERSION_STRING}")
        include_directories(${orcania_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Orcania version required: ${ORCANIA_VERSION_REQUIRED} - version installed: ${ORCANIA_VERSION_STRING}")
    endif ()
elseif (NOT ORCANIA_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    message(STATUS "Download Orcania ${ORCANIA_VERSION_REQUIRED}")
    download_project(PROJ orcania # ... otherwise, download archive
                     URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
    include_directories(${orcania_SOURCE_DIR}/include)
    add_dependencies(esras orcania)
    set(ORCANIA_LIBRARIES orcania)
    include_directories(${orcania_BINARY_DIR})
else ()
    message( FATAL_ERROR "Orcania not found")
endif ()
set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})

set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
include(FindYder)
find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
if (YDER_FOUND)
    if ("${YDER_VERSION_STRING}" VERSION_GREATER_EQUAL "${YDER_VERSION_REQUIRED}")
        message(STATUS "Yder found: ${YDER_VERSION_STRING}")
        include_directories(${yder_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Yder version required: ${YDER_VERSION_REQUIRED} - version installed: ${YDER_VERSION_STRING}")
    endif ()
elseif (NOT YDER_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    message(STATUS "Download Yder ${YDER_VERSION_REQUIRED}")
    option(CHECK_ORCANIA "specific param" off)
    download_project(PROJ yder # ... otherwise, download archive
                     URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
    include_directories(${yder_SOURCE_DIR}/include)
    include_directories(${orcania_SOURCE_DIR}/include)
    add_dependencies(glewlwyd yder)
    add_dependencies(yder orcania)
    set(YDER_LIBRARIES yder)
    include_directories(${yder_BINARY_DIR})
else ()
    message( FATAL_ERROR "Yder not found")
endif ()
set(LIBS ${LIBS} ${YDER_LIBRARIES})

set(Ulfius_FIND_QUIETLY ON)
include(FindUlfius)
find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
if (ULFIUS_FOUND)
    if ("${ULFIUS_VERSION_STRING}" VERSION_GREATER_EQUAL "${ULFIUS_VERSION_REQUIRED}")
        message(STATUS "Ulfius found: ${ULFIUS_VERSION_STRING}")
        include_directories(${ulfius_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Ulfius version required: ${ULFIUS_VERSION_REQUIRED} - version installed: ${ULFIUS_VERSION_STRING}")
    endif ()
elseif (NOT ULFIUS_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    option(WITH_WEBSOCKET "specific param" off)
    option(INSTALL_HEADER "specific param" off)
    option(CHECK_YDER "specific param" off)
    message(STATUS "Download Ulfius ${ULFIUS_VERSION_REQUIRED}")
    download_project(PROJ ulfius
                     URL "https://github.com/babelouest/ulfius/archive/v${ULFIUS_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${ulfius_SOURCE_DIR} ${ulfius_BINARY_DIR})
    include_directories(${yder_SOURCE_DIR}/include)
    include_directories(${orcania_SOURCE_DIR}/include)
    include_directories(${ulfius_SOURCE_DIR}/include)
    add_dependencies(esras ulfius)
    add_dependencies(ulfius yder)
    add_dependencies(ulfius orcania)
    set(ULFIUS_LIBRARIES ulfius)
    include_directories(${ulfius_BINARY_DIR})
else ()
    message( FATAL_ERROR "Ulfius not found")
endif ()
set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})

set(Hoel_FIND_QUIETLY ON)
include(FindHoel)
find_package(Hoel ${HOEL_VERSION_REQUIRED} QUIET)
if (HOEL_FOUND)
    if ("${HOEL_VERSION_STRING}" VERSION_GREATER_EQUAL "${HOEL_VERSION_REQUIRED}")
        message(STATUS "Hoel found: ${HOEL_VERSION_STRING}")
        include_directories(${hoel_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Hoel version required: ${HOEL_VERSION_REQUIRED} - version installed: ${HOEL_VERSION_STRING}")
    endif ()
elseif (NOT HOEL_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    option(INSTALL_HEADER "specific param" off)
    option(CHECK_YDER "specific param" off)
    message(STATUS "Download Hoel ${HOEL_VERSION_REQUIRED}")
    download_project(PROJ hoel
                     URL "https://github.com/babelouest/hoel/archive/v${HOEL_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${hoel_SOURCE_DIR} ${hoel_BINARY_DIR})
    include_directories(${hoel_SOURCE_DIR}/include)
    add_dependencies(glewlwyd hoel)
    add_dependencies(hoel yder)
    add_dependencies(hoel orcania)
    set(HOEL_LIBRARIES hoel)
    include_directories(${hoel_BINARY_DIR})
else ()
    message( FATAL_ERROR "Hoel not found")
endif ()
set(LIBS ${LIBS} ${HOEL_LIBRARIES})

set(Rhonabwy_FIND_QUIETLY ON) # force to find Rhonabwy quietly
include(FindRhonabwy)
find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET) # try to find rhonabwy
if (RHONABWY_FOUND)
    if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
        message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
        include_directories(${rhonabwy_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
    endif ()
elseif (NOT RHONABWY_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    message(STATUS "Download Rhonabwy ${RHONABWY_VERSION_REQUIRED}")
    download_project(PROJ rhonabwy # ... otherwise, download archive
                     URL "https://github.com/babelouest/rhonabwy/archive/v${RHONABWY_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${rhonabwy_SOURCE_DIR} ${rhonabwy_BINARY_DIR})
    include_directories(${rhonabwy_SOURCE_DIR}/include)
    set(RHONABWY_LIBRARIES rhonabwy)
    include_directories(${rhonabwy_BINARY_DIR})
    add_dependencies(rhonabwy orcania)
    add_dependencies(rhonabwy yder)
    add_dependencies(rhonabwy ulfius)
    add_dependencies(esras rhonabwy)
    set (RHONABWY_FOUND ON)
else ()
    message( FATAL_ERROR "Rhonabwy not found")
endif ()
set(LIBS ${LIBS} ${RHONABWY_LIBRARIES})

set(Iddawc_FIND_QUIETLY ON) # force to find Iddawc quietly
include(FindIddawc)
find_package(Iddawc ${IDDAWC_VERSION_REQUIRED} QUIET) # try to find iddawc
if (IDDAWC_FOUND)
    if ("${IDDAWC_VERSION_STRING}" VERSION_GREATER_EQUAL "${IDDAWC_VERSION_REQUIRED}")
        message(STATUS "Iddawc found: ${IDDAWC_VERSION_STRING}")
        include_directories(${iddawc_SOURCE_DIR}/include)
    else ()
        message( FATAL_ERROR "Iddawc version required: ${IDDAWC_VERSION_REQUIRED} - version installed: ${IDDAWC_VERSION_STRING}")
    endif ()
elseif (NOT IDDAWC_FOUND AND DOWNLOAD_DEPENDENCIES)
    include(DownloadProject)
    message(STATUS "Download Iddawc ${IDDAWC_VERSION_REQUIRED}")
    download_project(PROJ iddawc # ... otherwise, download archive
                     URL "https://github.com/babelouest/iddawc/archive/v${IDDAWC_VERSION_REQUIRED}.tar.gz"
                     QUIET)
    add_subdirectory(${iddawc_SOURCE_DIR} ${iddawc_BINARY_DIR})
    include_directories(${iddawc_SOURCE_DIR}/include)
    set(IDDAWC_LIBRARIES iddawc)
    include_directories(${iddawc_BINARY_DIR})
    set (IDDAWC_FOUND ON)
    add_dependencies(iddawc orcania)
    add_dependencies(iddawc yder)
    add_dependencies(iddawc ulfius)
    add_dependencies(iddawc rhonabwy)
    add_dependencies(esras iddawc)
else ()
    message( FATAL_ERROR "Iddawc not found")
endif ()
set(LIBS ${LIBS} ${IDDAWC_LIBRARIES})

target_link_libraries(esras ${LIBS})

# install target

install(TARGETS esras
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY webapp/
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/esras/webapp/ COMPONENT runtime)

set(TARGETS esras)

install(TARGETS ${TARGETS}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        CONFIGURATIONS Release)

# uninstall target

if (NOT TARGET uninstall)
    configure_file(
            "${E_CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)
    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

# packaging

set(CPACK_PACKAGE_VERSION_MAJOR ${PROGRAM_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROGRAM_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROGRAM_VERSION_PATCH})

set(PACKAGE_FILE_NAME
        "${CMAKE_PROJECT_NAME}_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

set(PACKAGE_IGNORED_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/;/.git/;.gitignore;~$;${CPACK_SOURCE_IGNORE_FILES}")

set(CPACK_GENERATOR "TGZ;DEB")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mail@babelouest.org")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/babelouest/esras")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.4), libconfig9, libgnutls30 (>= 3.5.0), liborcania|liborcania-dev (>= ${ORCANIA_VERSION_REQUIRED}), libyder|libyder-dev (>= ${YDER_VERSION_REQUIRED}), libulfius|libulfius-dev (>= ${ULFIUS_VERSION_REQUIRED}), libhoel|libhoel-dev (>= ${HOEL_VERSION_REQUIRED}), librhonabwy|librhonabwy-dev (>= ${RHONABWY_VERSION_REQUIRED}), libiddawc|libiddawc-dev (>= ${IDDAWC_VERSION_REQUIRED}), lsb-base (>= 3.0-6)")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

add_custom_target(dist
        COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

message(STATUS "Download required dependencies: ${DOWNLOAD_DEPENDENCIES}")
