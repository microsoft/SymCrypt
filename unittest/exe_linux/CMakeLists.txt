set(SOURCES
    main_exe.cpp
  )

add_executable(symcryptunittest ${SOURCES})
target_link_libraries(symcryptunittest symcryptunittest_lib symcrypt)