execute_process(COMMAND
  git symbolic-ref --short HEAD
  OUTPUT_VARIABLE SYMCRYPT_BUILD_INFO_BRANCH)
string(REGEX REPLACE "\n$" "" SYMCRYPT_BUILD_INFO_BRANCH "${SYMCRYPT_BUILD_INFO_BRANCH}")

execute_process(COMMAND
  git log -n 1 --date=iso-strict-local --format=%cd_%h
  OUTPUT_VARIABLE SYMCRYPT_BUILD_INFO_COMMIT)
string(REGEX REPLACE "\n$" "" SYMCRYPT_BUILD_INFO_COMMIT "${SYMCRYPT_BUILD_INFO_COMMIT}")

execute_process(COMMAND
  git symbolic-ref --short HEAD
  OUTPUT_VARIABLE SYMCRYPT_BUILD_INFO_VERSION)
string(REGEX REPLACE "\n$" "" SYMCRYPT_BUILD_INFO_VERSION "${SYMCRYPT_BUILD_INFO_VERSION}")

string(TIMESTAMP SYMCRYPT_BUILD_INFO_TIMESTAMP "%Y-%m-%dT%H:%M:%S")
configure_file(${CMAKE_SOURCE_DIR}/build/buildInfo.h.in ${CMAKE_SOURCE_DIR}/inc/buildInfo.h)
