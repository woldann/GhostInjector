cmake_minimum_required(VERSION 3.10)
project(GhostInjector VERSION 1.0.1 LANGUAGES C)

add_subdirectory(Neptune)
add_subdirectory(NThread)

string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)
set(EXECUTABLE_NAME "${PROJECT_NAME_LOWER}-${PROJECT_VERSION}")

add_executable(${EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE NThread)
target_compile_definitions(${EXECUTABLE_NAME} PRIVATE
  LOG_LEVEL_2
  NEPTUNE_MODULERULES_HEADER="nthread_rules.h"
  LOG_FORCE_COLOR
  VERSION=${PROJECT_VERSION}
)

