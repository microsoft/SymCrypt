# Require Windows 10 SDK version 18362 for BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG
set(CMAKE_SYSTEM_VERSION 10.0.18362)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV WindowsUserMode)

add_compile_options(-D_AMD64_)