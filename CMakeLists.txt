# https://gitlab.com/CLIUtils/modern-cmake/-/blob/master/examples/extended-project/CMakeLists.txt

cmake_minimum_required(VERSION 3.22)

# Project name and a few useful settings. Other commands can pick up the results
project(COMP8505_project
        VERSION 0.1
        DESCRIPTION ""
        LANGUAGES C)

set(HEADER_LIST
        "${PROJECT_SOURCE_DIR}/include/common.h"
        "${PROJECT_SOURCE_DIR}/include/extern.h"
        "${PROJECT_SOURCE_DIR}/include/victim.h"
        "${PROJECT_SOURCE_DIR}/include/attacker.h"
        )

set(COMMON_SOURCE_LIST
        "${PROJECT_SOURCE_DIR}/src/common.c"
        )

set(ATTACKER_SOURCE_LIST
        "${PROJECT_SOURCE_DIR}/src/attacker.c"
        )

set(VICTIM_SOURCE_LIST
        "${PROJECT_SOURCE_DIR}/src/victim.c"
        )


### Require out-of-source builds
# this still creates a CMakeFiles directory and CMakeCache.txt- can we delete them?
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if (EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif ()

# Only do these if this is the main project, and not if it is included through add_subdirectory
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

    # Optionally set things like CMAKE_CXX_STANDARD, CMAKE_POSITION_INDEPENDENT_CODE here
    set(CMAKE_C_STANDARD 17)
    set(CMAKE_C_EXTENSIONS OFF)

    # Let's nicely support folders in IDEs
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    # The compiled library code is here
    add_subdirectory(src)

endif ()