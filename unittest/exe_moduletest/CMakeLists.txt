set(SOURCES
    moduletest.cpp
  )

add_executable(symcryptmoduletest ${SOURCES})
target_link_libraries(symcryptmoduletest symcrypt)

add_dependencies(symcryptmoduletest symcrypt_fips)
