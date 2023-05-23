set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_executable(symcryptunittest_legacy ${SOURCES})
target_link_libraries(symcryptunittest_legacy symcryptunittest_lib symcrypt_generic bcrypt ntdll)

if(SYMCRYPT_TEST_LEGACY_IMPL)
    # For internal builds, append RSA32 and msbignum.
    # Calling target_link_libraries again appends to the existing list.
    target_link_libraries(symcryptunittest_legacy ${RSA32_LIB} ${MSBIGNUM_LIB})
endif()

add_dependencies(symcryptunittest_legacy symcrypttestmodule)
