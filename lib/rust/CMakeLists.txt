if(SYMCRUST_CONFIG STREQUAL "Off")
    message(FATAL_ERROR "We should not be invoking cargo unless we are doing a SymCrypt/SymCRust build!")
endif()

if(SYMCRYPT_TARGET_ARCH STREQUAL "X86" OR SYMCRYPT_TARGET_ARCH STREQUAL "ARM")
    message(FATAL_ERROR "SymCRust does not currently support the X86 or ARM")
endif()

if(SYMCRYPT_TARGET_ENV MATCHES "PosixUserMode")
    set(SYMCRUST_LIB_NAME "libsymcrust.a")
elseif(SYMCRYPT_TARGET_ENV MATCHES "WindowsUserMode")
    set(SYMCRUST_LIB_NAME "symcrust.lib")
else()
    message(FATAL_ERROR "Unsupported SymCRust target env")
endif()

if(CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo")
    set(SYMCRUST_CARGO_BUILD_FLAGS "--release")
    set(SYMCRUST_CARGO_BUILD_DIR "release" )
else()
    set(SYMCRUST_CARGO_BUILD_FLAGS "")
    set(SYMCRUST_CARGO_BUILD_DIR "debug" )
endif()

set(SYMCRUST_SOURCE_DIR ${SYMCRYPT_SOURCE_DIR}/SymCRust)

if(WIN32)
    if(SYMCRYPT_TARGET_ARCH STREQUAL "AMD64")
        set(SYMCRUST_TARGET_TRIPLE x86_64-pc-windows-msvc)
    elseif(SYMCRYPT_TARGET_ARCH STREQUAL "ARM64")
        set(SYMCRUST_TARGET_TRIPLE aarch64-pc-windows-msvc)
    endif()
else()
    if(SYMCRYPT_TARGET_ARCH STREQUAL "AMD64")
        set(SYMCRUST_TARGET_TRIPLE x86_64-unknown-linux-gnu)
    elseif(SYMCRYPT_TARGET_ARCH STREQUAL "ARM64")
        set(SYMCRUST_TARGET_TRIPLE aarch64-unknown-linux-gnu)
    endif()
endif()

# we are cross compiling in CMake (TARGET_TRIPLE is set in toolchain files)
if(DEFINED TARGET_TRIPLE)
    # FIXME: build-std is a nightly feature
    # build-std seems to be required for cross-compiling
    # this does take around a minute to build the first time
    set(SYMCRUST_CARGO_BUILD_FLAGS "-Zbuild-std=std" ${SYMCRUST_CARGO_BUILD_FLAGS})
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
    # SymCRust is linked into the C++ unit test. The prebuilt core/alloc shipped with the toolchain
    # are compiled with panic=unwind and reference rust_eh_personality, which is undefined when our
    # panic=abort staticlib is linked into C++. Rebuild core/alloc from source (nightly feature) so
    # they inherit our panic=abort profile and drop the personality reference.
    set(SYMCRUST_CARGO_BUILD_FLAGS "-Zbuild-std=core,alloc" ${SYMCRUST_CARGO_BUILD_FLAGS})
endif()

add_custom_target(
    symcrust_cargo ALL
    COMMAND ${Python3_EXECUTABLE} symcrust_cargo.py
        ${SYMCRUST_CONFIG}
        build
        --manifest-path ${SYMCRUST_SOURCE_DIR}/Cargo.toml
        --target-dir ${CMAKE_CURRENT_BINARY_DIR}
        --target ${SYMCRUST_TARGET_TRIPLE}
        ${SYMCRUST_CARGO_BUILD_FLAGS}
    WORKING_DIRECTORY ${SYMCRUST_SOURCE_DIR}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRUST_TARGET_TRIPLE}/${SYMCRUST_CARGO_BUILD_DIR}/${SYMCRUST_LIB_NAME})

add_library(symcrust STATIC IMPORTED GLOBAL)
set_property(TARGET symcrust PROPERTY
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRUST_TARGET_TRIPLE}/${SYMCRUST_CARGO_BUILD_DIR}/${SYMCRUST_LIB_NAME})
add_dependencies(symcrust symcrust_cargo)

target_link_libraries(symcrust INTERFACE symcrypt_common)