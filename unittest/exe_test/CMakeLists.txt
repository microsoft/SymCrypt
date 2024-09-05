set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_executable(symcryptunittest ${SOURCES})
target_link_libraries(symcryptunittest symcryptunittest_lib symcrypt_common bcrypt ntdll)

if(SYMCRYPT_TEST_LEGACY_IMPL)
    # For internal builds, append RSA32 and msbignum.
    # Calling target_link_libraries again appends to the existing list.
    target_link_libraries(symcryptunittest ${RSA32_LIB} ${MSBIGNUM_LIB})
endif()
