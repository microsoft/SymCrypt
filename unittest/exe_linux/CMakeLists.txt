set(SOURCES
    main_exe.cpp
  )

add_compile_options(-DINCLUDE_IMPL_CAPI=0)
add_compile_options(-DINCLUDE_IMPL_CNG=0)
add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
add_compile_options(-DINCLUDE_IMPL_RSA32=0)

add_executable(symcryptunittest ${SOURCES})
target_link_libraries(symcryptunittest symcryptunittest_lib symcrypt_common)