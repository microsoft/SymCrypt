set(SOURCES
    moduletest.cpp
)

add_executable(symcryptmoduletest_linux ${SOURCES})
target_link_libraries(symcryptmoduletest_linux symcrypt_linux)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
  add_executable(symcryptmoduletest_oe ${SOURCES})
  target_link_libraries(symcryptmoduletest_oe symcrypt_oe)

  add_dependencies(symcryptmoduletest_oe symcrypt_oe_fips)
endif()
