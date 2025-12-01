# toolchain-mingw.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Strip only in Release builds, not Debug
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_EXE_LINKER_FLAGS "-s")
    set(CMAKE_SHARED_LINKER_FLAGS "-s")
endif()

# Optimize for size in release builds
string(APPEND CMAKE_C_FLAGS_RELEASE " -Os")