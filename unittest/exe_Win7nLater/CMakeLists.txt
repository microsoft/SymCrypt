set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_compile_options(-DTESTDRIVER_NAME=\"SymCryptDriver_win7nlater.sys\")

# For external builds, do not include msbignum and RSA32 which are not licensed for external use
if(NOT SYMCRYPT_INTERNAL_BUILD)
    add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
    add_compile_options(-DINCLUDE_IMPL_RSA32=0)
endif()

add_executable(symcryptunittest_win7nlater ${SOURCES})
target_link_libraries(symcryptunittest_win7nlater symcryptunittest_lib symcrypt_usermodewin7 bcrypt ntdll)

if(SYMCRYPT_INTERNAL_BUILD)
    # For internal builds, append RSA32 and msbignum.
    # Calling target_link_libraries again appends to the existing list.
    target_link_libraries(symcryptunittest_win7nlater ${RSA32_LIB} ${MSBIGNUM_LIB})
endif()