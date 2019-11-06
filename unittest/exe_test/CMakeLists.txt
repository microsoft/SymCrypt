set(SOURCES
    main_exe.cpp
    symcryptunittest.rc
  )

set_source_files_properties(symcryptunittest.rc PROPERTIES LANGUAGE RC)

add_compile_options(-DTESTDRIVER_NAME=\"SymCryptDriver_test.sys\")

# Workaround for including ntintsafe.h
add_compile_options(-DCMAKE_COMPILE)

include_directories(${CMAKE_SOURCE_DIR}/SymCryptDependencies/inc)

add_executable(symcryptunittest_generic ${SOURCES})

find_library(RSA32_LIB rsa32.lib HINTS ${CMAKE_SOURCE_DIR}/SymCryptDependencies/amd64)
find_library(MSBIGNUM_LIB msbignum.lib HINTS ${CMAKE_SOURCE_DIR}/SymCryptDependencies/amd64)

target_link_libraries(symcryptunittest_generic symcryptunittest_lib symcrypt_generic bcrypt ntdll ${RSA32_LIB} ${MSBIGNUM_LIB})