cmake_minimum_required(VERSION 3.10)
project(GhostInjector VERSION 1.0.2 LANGUAGES C)

if(MSVC)
    string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
endif()

# MinGW debug symbols (DWARF embedded in exe)
if(MINGW AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -gdwarf-4")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -gdwarf-4")
endif()

# Set C standard to C99 for the entire project
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(WIN32)
    set(CMAKE_EXECUTABLE_SUFFIX ".exe")
endif()

add_subdirectory(Neptune)
add_subdirectory(NThread)
add_subdirectory(NThreadOSUtils)

# Testleri derlemeye dahil et
add_subdirectory(tests)

set(GHOSTINJECTOR_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(GHOSTINJECTOR_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE GHOSTINJECTOR_HEADERS CONFIGURE_DEPENDS ${GHOSTINJECTOR_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE GHOSTINJECTOR_SOURCES CONFIGURE_DEPENDS ${GHOSTINJECTOR_SOURCE_DIR}/*.c)

string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)
set(EXECUTABLE_NAME "${PROJECT_NAME_LOWER}-${PROJECT_VERSION}")

add_executable(${EXECUTABLE_NAME} ${GHOSTINJECTOR_SOURCES})
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${GHOSTINJECTOR_INCLUDE_DIR})
target_link_libraries(${EXECUTABLE_NAME} PRIVATE NThreadOSUtils)

# Debug build option for testers (enables LOG_LEVEL_3)
option(DEBUG_BUILD "Enable debug build with verbose logging (LOG_LEVEL_3)" OFF)

if(DEBUG_BUILD)
  set(LOG_LEVEL_DEF "LOG_LEVEL_3")
else()
  set(LOG_LEVEL_DEF "LOG_LEVEL_2")
endif()

target_compile_definitions(${EXECUTABLE_NAME} PRIVATE
  ${LOG_LEVEL_DEF}
  NEPTUNE_MODULERULES_HEADER="ntosutils_rules.h"
  NEPTUNE_ENABLE_MEMMEM
  VERSION=${PROJECT_VERSION}
  LOG_FILE_PATH=L"ghostinjector.log"
  LOG_ON_STDOUT=1
)