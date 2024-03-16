if(OPENSSL_BUILD_FROM_SOURCE)
    if(CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo")
        set(OPENSSL_BUILD_TYPE release)
    else()
        set(OPENSSL_BUILD_TYPE debug)
    endif()
    if(NOT DEFINED OPENSSL_BUILD_BRANCH)
        set(OPENSSL_BUILD_BRANCH_SUFFIX "")
    else()
        set(OPENSSL_BUILD_BRANCH_SUFFIX -${OPENSSL_BUILD_BRANCH})
    endif()

    set(OPENSSL_BUILD_ROOT ${CMAKE_SOURCE_DIR}/3rdparty/openssl-${OPENSSL_BUILD_TYPE}${OPENSSL_BUILD_BRANCH_SUFFIX})

    if(NOT IS_DIRECTORY "${OPENSSL_BUILD_ROOT}" OR NOT EXISTS "${OPENSSL_BUILD_ROOT}/Configure")
        execute_process(
            COMMAND git clone https://github.com/openssl/openssl.git ${OPENSSL_BUILD_ROOT}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
        if(NOT OPENSSL_BUILD_BRANCH STREQUAL "")
            execute_process(
                COMMAND git checkout ${OPENSSL_BUILD_BRANCH}
                WORKING_DIRECTORY ${OPENSSL_BUILD_ROOT})
        endif()
    endif()

    if(NOT EXISTS "${OPENSSL_BUILD_ROOT}/OpenSSLConfig.cmake")
        set(ENV{LANG} C)
        set(ENV{LC_ALL} C)
        set(ENV{CL} /MP)
        if(OPENSSL_BUILD_TYPE STREQUAL "release")
            execute_process(
                COMMAND perl Configure no-ssl no-tls1 no-tls1_1 --release
                WORKING_DIRECTORY ${OPENSSL_BUILD_ROOT}
                RESULT_VARIABLE result)
        else()
            execute_process(
                COMMAND perl Configure no-ssl no-tls1 no-tls1_1 --debug
                WORKING_DIRECTORY ${OPENSSL_BUILD_ROOT}
                RESULT_VARIABLE result)
        endif()
        if(CMAKE_SYSTEM_NAME MATCHES "Linux")
            cmake_host_system_information(RESULT J
                QUERY NUMBER_OF_LOGICAL_CORES)

            execute_process(
                COMMAND make -j ${J}
                WORKING_DIRECTORY ${OPENSSL_BUILD_ROOT}
                RESULT_VARIABLE result)
        elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
            execute_process(
                COMMAND nmake
                WORKING_DIRECTORY ${OPENSSL_BUILD_ROOT}
                RESULT_VARIABLE result)
        else()
            message(FATAL_ERROR "Unsupported platform")
        endif()
    endif()

    # If you don't static link, symcryptunittest.exe may use C:\WINDOWS\SYSTEM32\libcrypto-3-x64.dll
    set(OPENSSL_USE_STATIC_LIBS True)

    include(${OPENSSL_BUILD_ROOT}/OpenSSLConfig.cmake)
else()
    find_package(OpenSSL REQUIRED)
endif()

message("Found OpenSSL include directory ${OPENSSL_INCLUDE_DIR}")
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})
link_libraries(${OPENSSL_CRYPTO_LIBRARIES})
add_compile_options(-DINCLUDE_IMPL_OPENSSL=1)
