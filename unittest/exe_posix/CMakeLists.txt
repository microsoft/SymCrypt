set(SOURCES
    main_exe.cpp
  )

if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64|X86")
  if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    set_source_files_properties(main_exe.cpp PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
  endif()
endif()

add_compile_definitions(INCLUDE_IMPL_CAPI=0)
add_compile_definitions(INCLUDE_IMPL_CNG=0)
add_compile_definitions(INCLUDE_IMPL_MSBIGNUM=0)
add_compile_definitions(INCLUDE_IMPL_RSA32=0)

add_executable(symcryptunittest ${SOURCES})
target_link_libraries(symcryptunittest symcryptunittest_lib symcrypt_common dl)

# Special linking options for macOS
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  find_library(SECURITY_FRAMEWORK Security REQUIRED)
  target_link_libraries(symcryptunittest ${SECURITY_FRAMEWORK})

  # macOS-specific hack: we need to run dsymutil to produce debug symbols, because the macOS
  # linker doesn't do this itself. Xcode does this for you (including when using the CMake
  # XCode generator), but when using the makefile generator, which directly invokes clang,
  # it does not happen automatically. Thus, we need an extra step to generate symbols.
  add_custom_command(
      TARGET symcryptunittest POST_BUILD
      COMMAND xcrun dsymutil $<TARGET_FILE:symcryptunittest> -o $<TARGET_FILE_DIR:symcryptunittest>/symcryptunittest.dSYM
    )
else() # Special linking options for non-MacOS
    target_link_libraries(symcryptunittest atomic)
endif()

# Export oe_sgx_get_additional_host_entropy from the executable so that if we dynamically load
# oe module, the linker can find the version which is locally defined in the executable
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  target_link_options(symcryptunittest PRIVATE
    -Wl,--dynamic-list=${CMAKE_CURRENT_SOURCE_DIR}/dynamic-list.ver
  )
endif()
