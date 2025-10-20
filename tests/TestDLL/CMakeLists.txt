cmake_minimum_required(VERSION 3.10)
project(TestDLL C)

set(CMAKE_C_STANDARD 99)

string(TOLOWER ${PROJECT_NAME} library_name)

add_library(${library_name} SHARED src/dllmain.c)

target_include_directories(${library_name} PRIVATE ../../Neptune/include)

target_link_libraries(${library_name} PRIVATE Neptune)

target_compile_definitions(${library_name} PRIVATE
  LOG_LEVEL_2
  "LOG_FILE_PATH=L\"C:\\\\ghostinjectortest.log\""
  LOG_ON_STDOUT=0
)

set_target_properties(${library_name} PROPERTIES PREFIX "")
