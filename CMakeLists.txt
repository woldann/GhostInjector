cmake_minimum_required(VERSION 3.15)
project(GhostInjector VERSION 1.0.2 LANGUAGES C CXX)

# Enable new policy for MSVC runtime library selection
cmake_policy(SET CMP0091 NEW)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use static C/C++ runtime (/MT) instead of dynamic (/MD)
# This embeds the runtime into the executable (no VCRUNTIME/MSVCP DLLs needed)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  
  # Alternative: Set compiler flags directly for older CMake versions
  set(CompilerFlags
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
  )
  foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
  endforeach()
endif()

add_subdirectory(Neptune)
add_subdirectory(NThread)
add_subdirectory(NThreadOSUtils)

set(GHOSTINJECTOR_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(GHOSTINJECTOR_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE GHOSTINJECTOR_HEADERS CONFIGURE_DEPENDS ${GHOSTINJECTOR_INCLUDE_DIR}/*.h ${GHOSTINJECTOR_INCLUDE_DIR}/*.hpp)
file(GLOB_RECURSE GHOSTINJECTOR_SOURCES CONFIGURE_DEPENDS ${GHOSTINJECTOR_SOURCE_DIR}/*.c ${GHOSTINJECTOR_SOURCE_DIR}/*.cpp)

string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)
set(EXECUTABLE_NAME "${PROJECT_NAME_LOWER}-${PROJECT_VERSION}")

add_executable(${EXECUTABLE_NAME} ${GHOSTINJECTOR_SOURCES})
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${GHOSTINJECTOR_INCLUDE_DIR})
target_link_libraries(${EXECUTABLE_NAME} PRIVATE NThreadOSUtils)

target_compile_definitions(${EXECUTABLE_NAME} PRIVATE
  LOG_LEVEL_2
  NEPTUNE_MODULERULES_HEADER="ntosutils_rules.h"
  NEPTUNE_ENABLE_MEMMEM
  VERSION=${PROJECT_VERSION}
  LOG_FILE_PATH=L"ghostinjector.log"
  LOG_ON_STDOUT=1
)

