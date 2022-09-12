set(SOURCES
    main_exe.cpp
  )

if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
  if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    set_source_files_properties(main_exe.cpp PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
  endif()
endif()

add_compile_options(-DINCLUDE_IMPL_CAPI=0)
add_compile_options(-DINCLUDE_IMPL_CNG=0)
add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
add_compile_options(-DINCLUDE_IMPL_RSA32=0)

add_executable(symcryptunittest ${SOURCES})
target_link_libraries(symcryptunittest symcryptunittest_lib symcrypt_common atomic dl)

# Export oe_sgx_get_additional_host_entropy from the executable so that if we dynamically load
# oe module, the linker can find the version which is locally defined in the executable
target_link_options(symcryptunittest PRIVATE 
  -Wl,--dynamic-list=${CMAKE_CURRENT_SOURCE_DIR}/dynamic-list.ver
)
