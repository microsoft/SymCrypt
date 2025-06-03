# Request C++17 standard to enable `if constexpr`
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create variable in caller scope name where
# "." are converted into "_" in input_file.
function(make_cxx_name input_file name)
#  string(REGEX REPLACE "\\." "_" ${name} ${input_file})
  string(REPLACE "." "_" ${name} ${input_file})
  set(${name} ${${name}} PARENT_SCOPE)
endfunction()

function(make_includable input_file output_file cxx_name)
  file(READ ${input_file} content)
  set(delim "for_c++_include")
  set(content
      "static const char ${cxx_name}[] = R\"${delim}(\n${content})${delim}\";"
    )
  file(WRITE ${output_file} "#pragma once\n${content}\n")
endfunction()

function(dat_to_h files)
  foreach(f ${files})
    get_filename_component(basename ${f} NAME)
    make_cxx_name(${basename} cxx_name)
    message("** Creating ${basename}.h with cxx name ${cxx_name}")
    make_includable(${f} "${CMAKE_BINARY_DIR}/inc/${basename}.h" ${cxx_name})
  endforeach()
endfunction()

function(create_resource_h data_files)
  message("** Creating resource.h")
  set(resource_file ${CMAKE_BINARY_DIR}/inc/resource.h)
  file(WRITE ${resource_file} "#pragma once\n")

  foreach(f ${data_files})
    get_filename_component(basename ${f} NAME)
    file(APPEND ${resource_file} "#include \"${basename}.h\"\n")
  endforeach()

  file(APPEND ${resource_file} "\n")

  file(APPEND ${resource_file}
    "static inline\n"
    )

  file(APPEND ${resource_file}
    "size_t GetResourceBytes(const char *resourceName, const char **bytes)\n{\n"
    )

  set(t "    ")

  foreach(f ${data_files})
    get_filename_component(basename ${f} NAME)
    make_cxx_name(${basename} cxx_name)
    file(APPEND ${resource_file}
      "${t}if (strcasecmp(resourceName, \"${basename}\") == 0) {\n"
      )
    file(APPEND ${resource_file}
      "${t}${t}*bytes = ${cxx_name};\n"
      )
    file(APPEND ${resource_file}
      "${t}${t}return sizeof(${cxx_name});\n"
      )
    file(APPEND ${resource_file}
      "${t}}\n"
      )
  endforeach()
  file(APPEND ${resource_file}
    "${t}return 0;\n}\n"
    )
endfunction()

file(GLOB DATA_FILES *.dat)

if(NOT WIN32)
    dat_to_h("${DATA_FILES}")
    create_resource_h("${DATA_FILES}")
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/Zc:strictStrings->)
endif()

if(SYMCRYPT_TEST_WITH_OPENSSL)
    include(${SYMCRYPT_SOURCE_DIR}/cmake-configs/OpenSSL.cmake)
    link_directories(${OPENSSL_LIBRARY_DIR})
    link_libraries(${OPENSSL_CRYPTO_LIBRARIES})
    add_compile_definitions(INCLUDE_IMPL_OPENSSL=1)
endif()

if(SYMCRYPT_TEST_LIBCRUX)
    message(STATUS "Temporarily not building with libcrux (awaiting Final MlKem implementation)")
    set(SYMCRYPT_TEST_LIBCRUX OFF)

    # if(NOT IS_DIRECTORY "${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages")
    #   execute_process(
    #     COMMAND git submodule update --init -- 3rdparty/hacl-packages
    #     WORKING_DIRECTORY ${SYMCRYPT_SOURCE_DIR})
    # endif()
    # file(TOUCH ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/include/LowStar_Ignore.h)

    # set(LIBCRUX_SOURCES
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/src/Hacl_Hash_SHA3.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/src/Hacl_Hash_SHA3_Scalar.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/core.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/Eurydice.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/libcrux_hacl_glue.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/libcrux_kyber512.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/libcrux_kyber768.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/libcrux_kyber1024.c
    #     ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/src/LowStar_Ignore.c)

    # if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
    #     list(APPEND LIBCRUX_SOURCES
    #         ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/src/Hacl_Hash_SHA3_Simd256.c)
    # endif()

    # add_library(libcrux STATIC ${LIBCRUX_SOURCES})
    # target_include_directories(libcrux PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/include)
    # target_include_directories(libcrux PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/karamel/include)
    # target_include_directories(libcrux PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/include)
    # target_include_directories(libcrux PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/karamel/krmllib/dist/minimal)

    # target_compile_definitions(libcrux PRIVATE HACL_CAN_COMPILE_VEC128)
    # if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
    #     target_compile_definitions(libcrux PRIVATE HACL_CAN_COMPILE_VEC256)
    # endif()

    # link_libraries(libcrux)

    # if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    #   target_compile_options(libcrux PRIVATE /wd4267)
    #   add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/wd4576>)
    #   add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/wd4200>)
    # endif()

    # if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    #   set_source_files_properties(${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/src/Hacl_Hash_SHA3_Simd256.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;")
    # endif()

    # add_compile_definitions(INCLUDE_IMPL_LIBCRUX=1)
endif()

if(SYMCRYPT_SYMCRUST MATCHES "ON")
  # When building with experimental SymCRust implementations, some
  # implementation-specific tests need to be disabled/changed
  add_compile_definitions(SYMCRUST_EXPERIMENTAL_BUILD=1)
endif()

include_directories(inc)
include_directories(lib)
include_directories(resource)

if(SYMCRYPT_TEST_LEGACY_IMPL)
  find_library(RSA32_LIB rsa32.lib HINTS SymCryptDependencies/${SYMCRYPT_TARGET_ARCH})
  find_library(MSBIGNUM_LIB msbignum.lib HINTS SymCryptDependencies/${SYMCRYPT_TARGET_ARCH})

  include_directories(SymCryptDependencies/inc)
else()
  # For external builds, do not include msbignum and RSA32 which are not licensed for external use
  add_compile_definitions(INCLUDE_IMPL_MSBIGNUM=0)
  add_compile_definitions(INCLUDE_IMPL_RSA32=0)
endif()

add_subdirectory(lib)

if(WIN32)
  add_subdirectory(exe_test)
  add_subdirectory(exe_legacy)
  add_subdirectory(exe_Win7nlater)
  add_subdirectory(exe_Win8_1nLater)
  add_subdirectory(module_windows)
else()
  add_subdirectory(exe_posix)
endif()