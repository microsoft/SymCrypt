if(NOT SYMCRYPT_SYMCRUST MATCHES "ON")
    message(FATAL_ERROR "We should not be invoking cargo unless we are doing a SymCrypt/SymCRust build!")
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

add_custom_target(
    symcrust_cargo ALL
    COMMAND cargo +nightly-2024-10-23
        build
        --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
        --target-dir ${CMAKE_CURRENT_BINARY_DIR}
        ${SYMCRUST_CARGO_BUILD_FLAGS}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRUST_CARGO_BUILD_DIR}/${SYMCRUST_LIB_NAME})

add_library(symcrust STATIC IMPORTED GLOBAL)
set_property(TARGET symcrust PROPERTY
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRUST_CARGO_BUILD_DIR}/${SYMCRUST_LIB_NAME})

target_link_libraries(symcrust INTERFACE symcrypt_common)
  
  