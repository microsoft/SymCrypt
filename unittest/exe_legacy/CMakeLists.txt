set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_compile_options(-DTESTDRIVER_NAME=\"SymCryptDriver_legacy.sys\")

# For external builds, do not include msbignum and RSA32 which are not licensed for external use
if(NOT SYMCRYPT_INTERNAL_BUILD)
    add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
    add_compile_options(-DINCLUDE_IMPL_RSA32=0)
else()
    include_directories(${CMAKE_SOURCE_DIR}/SymCryptDependencies/inc)
endif()

add_executable(symcryptunittest_legacy ${SOURCES})

if(NOT SYMCRYPT_INTERNAL_BUILD)
    target_link_libraries(symcryptunittest_legacy symcryptunittest_lib symcrypt_generic bcrypt ntdll)
else()
    find_library(RSA32_LIB rsa32.lib HINTS ${CMAKE_SOURCE_DIR}/SymCryptDependencies/${SYMCRYPT_TARGET_ARCH})
    find_library(MSBIGNUM_LIB msbignum.lib HINTS ${CMAKE_SOURCE_DIR}/SymCryptDependencies/${SYMCRYPT_TARGET_ARCH})
    target_link_libraries(symcryptunittest_legacy symcryptunittest_lib symcrypt_generic bcrypt ntdll ${RSA32_LIB} ${MSBIGNUM_LIB})
endif()