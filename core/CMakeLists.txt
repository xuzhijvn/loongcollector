# Copyright 2022 iLogtail Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.22)
project(loongcollector)

include(CMakeDependentOption)

# variable LINUX is supported in cmake version 3.25
# for now, explicitly set LINUX to true if the platform is linux
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(LINUX TRUE)
endif ()

# Options.
option(BUILD_LOGTAIL "Build Logtail executable and tools" ON)
# Used under the Android environment.
option(BUILD_LOGTAIL_SHARED_LIBRARY "Build Logtail shared library")
option(ENABLE_ENTERPRISE "enable enterprise feature")
cmake_dependent_option(ENABLE_COMPATIBLE_MODE "Build Logtail in compatible mode (for low version Linux)" OFF "LINUX" OFF)
cmake_dependent_option(ENABLE_STATIC_LINK_CRT "Build Logtail by linking CRT statically" OFF "LINUX" OFF)
cmake_dependent_option(ENABLE_CORP_FEATURE "Enable corp feature" OFF "ENABLE_ENTERPRISE" OFF)
option(WITHOUTGDB "Build Logtail without gdb")
option(WITHSPL "Build Logtail and UT with SPL" ON)
option(BUILD_LOGTAIL_UT "Build unit test for Logtail")
cmake_dependent_option(ENABLE_ADDRESS_SANITIZER "Enable address sanitizer" ON "CMAKE_BUILD_TYPE STREQUAL Debug;NOT ANDROID" OFF)
set(PROVIDER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/provider CACHE PATH "Path to the provider module") # external provider path can be set with -DPROVIDER_PATH
set(UNITTEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/unittest CACHE PATH "Path to the unittest module") # external unittest path can be set with -DUNITTEST_PATH

if (BUILD_LOGTAIL_SHARED_LIBRARY AND WITHSPL)
    message(FATEL_ERROR, "Generating logtail shared library is not supported to be linked with SPL. WITHSPL should be set OFF.")
    return()
endif()

if (ENABLE_ENTERPRISE)
    message(STATUS "Enable Enterprise Feature.")
    add_definitions(-D__ENTERPRISE__)
    include(${CMAKE_CURRENT_SOURCE_DIR}/enterprise_options.cmake)
    if (ENABLE_CORP_FEATURE)
        message(STATUS "Enable Corp Feature.")
        add_definitions(-D__CORP__)
    endif ()
else ()
    include(${CMAKE_CURRENT_SOURCE_DIR}/options.cmake)
endif ()

if (NOT WITHSPL)
    add_definitions(-D__EXCLUDE_SPL__)
endif()

add_definitions(-DXXH_DISPATCH_AVX2=0)
add_definitions(-DXXH_DISPATCH_AVX512=0)

# Default C/CXX flags.
if (UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -fpic -fPIC -D_LARGEFILE64_SOURCE")
    if (NOT WITHOUTGDB)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb")
    endif ()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
    string(REPLACE "-O3" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "-O3" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    if (BUILD_LOGTAIL_UT)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
    endif ()
elseif (MSVC)
    add_definitions(-DNOMINMAX)
    add_definitions(-DTARGETLIBS=Psapi.lib)
    add_definitions(-DPSAPI_VERSION=1)
    # remove WinSock1
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /MP /Zi")
    # /DEBUG will generate many "pdb not found" warnings.
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_STATIC_LINKER_FLAGS_RELEASE "${CMAKE_STATIC_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd /MP")
    add_compile_options("/std:c++17")
    # for cross-platform, soure file all are utf8
    add_compile_options("/utf-8")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()

# To be compatible with low version Linux.
if (ENABLE_COMPATIBLE_MODE)
    message(STATUS "Enable compatible mode.")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--wrap=memcpy")
    add_definitions(-DENABLE_COMPATIBLE_MODE)
endif ()

if (ANDROID OR CMAKE_BUILD_TYPE MATCHES Debug)
    set(NO_TCMALLOC TRUE)
    add_definitions(-DLOGTAIL_NO_TC_MALLOC)
endif ()

# Dependencies.
include(${CMAKE_CURRENT_SOURCE_DIR}/utils.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/dependencies.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/links.cmake)
set(PLUGIN_SOURCE_FILES_CORE "")
set(PLUGIN_SOURCE_FILES_SPL "")
include(${CMAKE_CURRENT_SOURCE_DIR}/common/common.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/common/links.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/input/input.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/input/links.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/processor/processor.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/processor/links.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/flusher/flusher.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/plugin/flusher/links.cmake)

# Subdirectories (modules). except for common, input, processor, flusher, observer, helper, spl, and provider.
set(SUB_DIRECTORIES_LIST
        application app_config checkpoint container_manager metadata logger go_pipeline monitor monitor/metric_constants monitor/metric_models monitor/profile_sender models
        config config/watcher constants
        collection_pipeline collection_pipeline/batch collection_pipeline/limiter collection_pipeline/plugin collection_pipeline/plugin/creator collection_pipeline/plugin/instance collection_pipeline/plugin/interface collection_pipeline/queue collection_pipeline/route collection_pipeline/serializer
        task_pipeline
        runner runner/sink/http
        protobuf/sls protobuf/models protobuf/forward
        file_server file_server/event file_server/event_handler file_server/event_listener file_server/reader file_server/polling
        parser
        )
if (LINUX)
    if (ENABLE_ENTERPRISE)
        set(SUB_DIRECTORIES_LIST ${SUB_DIRECTORIES_LIST} shennong shennong/sdk)
    endif()
    set(SUB_DIRECTORIES_LIST ${SUB_DIRECTORIES_LIST} ebpf ebpf/type ebpf/type/table ebpf/util ebpf/util/sampler ebpf/protocol/http ebpf/protocol ebpf/plugin/file_security ebpf/plugin/network_observer ebpf/plugin/process_security ebpf/plugin/network_security ebpf/plugin ebpf/observer ebpf/security
        prometheus prometheus/labels prometheus/schedulers prometheus/async prometheus/component
        host_monitor host_monitor/collector forward forward/loongsuite
        )
elseif(MSVC)
endif ()
if (ENABLE_ENTERPRISE)
    set(SUB_DIRECTORIES_LIST ${SUB_DIRECTORIES_LIST} config_sdk)
endif()

# Module includes & set files.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories("${DEPS_INCLUDE_ROOT}/coolbpf")

foreach (DIR_NAME ${SUB_DIRECTORIES_LIST})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${DIR_NAME})
endforeach (DIR_NAME)

foreach (DIR_NAME ${SUB_DIRECTORIES_LIST})
    file(GLOB TEMP_SOURCE_FILES ${DIR_NAME}/*.c ${DIR_NAME}/*.cc ${DIR_NAME}/*.cpp)
    list(APPEND FRAMEWORK_SOURCE_FILES ${TEMP_SOURCE_FILES})
endforeach (DIR_NAME)

if (ENABLE_ENTERPRISE)
    # remove several files in shennong/sdk
    list(REMOVE_ITEM FRAMEWORK_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/shennong/sdk/sample.cpp)
endif()

# remove several files in go_pipeline
list(REMOVE_ITEM FRAMEWORK_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/go_pipeline/LogtailPluginAdapter.cpp ${CMAKE_CURRENT_SOURCE_DIR}/go_pipeline/LogtailPluginAdapter.h)

if(MSVC)
    # remove linux event listener
    file(GLOB REMOVE_EVENT_LISTENER_SOURCES file_server/event_listener/*_Linux.cpp file_server/event_listener/*_Linux.h)
    list(REMOVE_ITEM FRAMEWORK_SOURCE_FILES ${REMOVE_EVENT_LISTENER_SOURCES})
elseif(UNIX)
    # remove windows event listener
    file(GLOB REMOVE_EVENT_LISTENER_SOURCES file_server/event_listener/*_Windows.cpp file_server/event_listener/*_Windows.h)
    list(REMOVE_ITEM FRAMEWORK_SOURCE_FILES ${REMOVE_EVENT_LISTENER_SOURCES})
    if (LINUX)
        if (WITHSPL)
            set(SRC_FILES ${PLUGIN_SOURCE_FILES_SPL})
        endif()
    endif()
endif()
set(SRC_FILES ${SRC_FILES} ${FRAMEWORK_SOURCE_FILES} ${PLUGIN_SOURCE_FILES_CORE})

# Logtail executable or shared library.
if (BUILD_LOGTAIL)
    # add provider
    set(PROVIDER_BASE_TARGET "provider")
    add_subdirectory("${PROVIDER_PATH}" ${CMAKE_BINARY_DIR}/${PROVIDER_BASE_TARGET})
    if (ENABLE_ENTERPRISE)
        if (UNIX)
            add_executable(${LOGTAIL_TARGET} enterprise_logtail.cpp ${SRC_FILES})
        elseif (MSVC)
            add_executable(${LOGTAIL_TARGET} enterprise_logtail_windows.cpp ${SRC_FILES})
        endif ()
    else ()
        if (UNIX)
            add_executable(${LOGTAIL_TARGET} logtail.cpp ${SRC_FILES})
        elseif (MSVC)
            add_executable(${LOGTAIL_TARGET} logtail_windows.cpp ${SRC_FILES})
        endif ()
    endif()
endif()

if (BUILD_LOGTAIL_SHARED_LIBRARY)  
    # add provider
    set(PROVIDER_BASE_TARGET "provider")
    add_subdirectory("${PROVIDER_PATH}" ${CMAKE_BINARY_DIR}/${PROVIDER_BASE_TARGET})
    if (ENABLE_ENTERPRISE)
        if (UNIX)
            add_library(${LOGTAIL_TARGET} SHARED enterprise_logtail.cpp ${SRC_FILES})
        elseif (MSVC)
            add_library(${LOGTAIL_TARGET} SHARED enterprise_logtail_windows.cpp ${SRC_FILES})
        endif ()
    else ()
        if (UNIX)
            add_library(${LOGTAIL_TARGET} SHARED logtail.cpp ${SRC_FILES})
        elseif (MSVC)
            add_library(${LOGTAIL_TARGET} SHARED logtail_windows.cpp ${SRC_FILES})
        endif ()
    endif()
endif ()

# Generate independent libraries.
add_subdirectory(go_pipeline)
add_subdirectory(common)
# Build eBPF dependencies
set(EBPF_DIRVER_TARGET "eBPFDriver")
add_subdirectory(ebpf/driver)
if(MSVC)
    if (ENABLE_ENTERPRISE)
        add_subdirectory(windows/daemon)
        add_subdirectory(windows/installer)
    endif()
endif()

# Link libraries.
if(BUILD_LOGTAIL OR BUILD_LOGTAIL_SHARED_LIBRARY)
    input_link(${LOGTAIL_TARGET})
    processor_link(${LOGTAIL_TARGET} ${WITHSPL})
    flusher_link(${LOGTAIL_TARGET})
    all_link(${LOGTAIL_TARGET})
    common_link(${LOGTAIL_TARGET})
    target_link_libraries(${LOGTAIL_TARGET} provider)
    if (LINUX)
        add_dependencies(${LOGTAIL_TARGET} install_coolbpf)
    endif()
endif()

# Logtail UT.
if (BUILD_LOGTAIL_UT)
    message(STATUS "Build unittest.")    
    function(delete_gcda_files target_directory)
        if(EXISTS "${target_directory}")
            message(STATUS "Deleting .gcda files in ${target_directory}")
            file(GLOB_RECURSE gcda_files "${target_directory}/*.gcda")
            foreach(gcda_file ${gcda_files})
                file(REMOVE "${gcda_file}")
            endforeach()
        endif()
    endfunction()
    delete_gcda_files(".")
    include(CTest)
    enable_testing()
    add_subdirectory("${UNITTEST_PATH}" "${CMAKE_BINARY_DIR}/unittest")
endif ()