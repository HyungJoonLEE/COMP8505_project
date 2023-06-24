add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
add_definitions(-D_BSD_SOURCE)

if(APPLE)
    add_definitions(-D_DARWIN_C_SOURCE)
endif()

find_program(LINT "clang-tidy")
IF (LINT)
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cert-dcl03-c,-hicpp-static-assert,-misc-static-assert,-altera-struct-pack-align,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling;--quiet")
ENDIF ()

include(FindPCAP.cmake)

# Make an executable
add_executable(ATTACKER ${COMMON_SOURCE_LIST} ${ATTACKER_SOURCE_LIST} ${HEADER_LIST})
add_executable(VICTIM ${COMMON_SOURCE_LIST} ${VICTIM_SOURCE_LIST} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(ATTACKER PRIVATE ../include)
target_include_directories(ATTACKER PRIVATE /usr/include)
target_include_directories(ATTACKER PRIVATE /usr/local/include)
target_link_directories(ATTACKER PRIVATE /usr/lib)
target_link_directories(ATTACKER PRIVATE /usr/local/lib)
target_link_directories(ATTACKER PRIVATE /usr/local/opt/openssl/lib)
target_link_libraries(ATTACKER PRIVATE ssl crypto)

target_include_directories(VICTIM PRIVATE ../include)
target_include_directories(VICTIM PRIVATE /usr/include)
target_include_directories(VICTIM PRIVATE /usr/local/include)
target_link_directories(VICTIM PRIVATE /usr/lib)
target_link_directories(VICTIM PRIVATE /usr/local/lib)
target_link_directories(VICTIM PRIVATE /usr/local/opt/openssl/lib)
target_link_libraries(VICTIM PRIVATE ssl crypto)


# All users of this library will need at least C17
target_compile_features(ATTACKER PUBLIC c_std_17)
target_compile_options(ATTACKER PRIVATE -g)
target_compile_options(ATTACKER PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(ATTACKER PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(ATTACKER PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)

target_compile_features(VICTIM PUBLIC c_std_17)
target_compile_options(VICTIM PRIVATE -g)
target_compile_options(VICTIM PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(VICTIM PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(VICTIM PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)


find_library(LIBM m REQUIRED)
find_library(LIBSOCKET socket)

target_link_libraries(ATTACKER PRIVATE ${LIBM})
target_link_libraries(ATTACKER PRIVATE ${PCAP_LIBRARY})
set_target_properties(ATTACKER PROPERTIES OUTPUT_NAME "attacker")

target_link_libraries(VICTIM PRIVATE ${LIBM})
target_link_libraries(VICTIM PRIVATE ${PCAP_LIBRARY})
set_target_properties(VICTIM PROPERTIES OUTPUT_NAME "victim")




install(TARGETS ATTACKER DESTINATION bin)
install(TARGETS VICTIM DESTINATION bin)


# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)

add_custom_target(
        format
        COMMAND clang-format
        -i
        ${HEADER_LIST}
        ${COMMON_SOURCE_LIST}
        ${ATTACKER_SOURCE_LIST}
        ${VICTIM_SOURCE_LIST}
)
