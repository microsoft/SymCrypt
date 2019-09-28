set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_compile_options(-DTESTDRIVER_NAME=\"SymCryptDriver_legacy.sys\")

# Workaround for including ntintsafe.h
add_compile_options(-DCMAKE_COMPILE)

include_directories(${CMAKE_SOURCE_DIR}/../symcryptpublics)

add_executable(symcryptunittest_legacy ${SOURCES})

find_library(RSA32_LIB rsa32.lib HINTS ${CMAKE_SOURCE_DIR}/../symcryptpublics/amd64)
find_library(MSBIGNUM_LIB msbignum.lib HINTS ${CMAKE_SOURCE_DIR}/../symcryptpublics/amd64)

target_link_libraries(symcryptunittest_legacy symcryptunittest_lib symcrypt_generic bcrypt ntdll ${RSA32_LIB} ${MSBIGNUM_LIB})