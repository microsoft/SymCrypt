# This file contains platform/architecture specific configuration info for SymCrypt

# Choose which environment to use based on the host platform
# We don't support cross-compiling from one platform to another (e.g. compiling Windows binaries on Linux)
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(SYMCRYPT_TARGET_ENV "LinuxUserMode")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(SYMCRYPT_TARGET_ENV "WindowsUserMode")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# Normalize architecture names, which vary across platforms. SymCrypt uses Windows architecture names.
if(NOT DEFINED SYMCRYPT_TARGET_ARCH)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(SYMCRYPT_TARGET_ARCH "AMD64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "[Xx]86|i[3456]86")
        set(SYMCRYPT_TARGET_ARCH "X86")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(SYMCRYPT_TARGET_ARCH "ARM64")
    else()
        message(FATAL_ERROR "Unsupported architecture")
    endif()
endif()

# Platform/architecture specific compiler options
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(SYMCRYPT_USE_ASM)
        enable_language(ASM)
        set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")
        # Suppress noisy warnings about compile options which are ignored for ASM
        # Less messy than restricting most of the below options to only C/CXX!
        add_compile_options($<$<COMPILE_LANGUAGE:ASM>:-Wno-unused-command-line-argument>)
    endif()

    # Architecture-specific compiler flags
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        # Enable a baseline of features for the compiler to support everywhere
        # Other than SSSE3 we do not expect the compiler to generate these instructions except with intrinsics
        #
        # We cannot globally enable AVX and later, as we need to keep use of these instructions behind CPU detection,
        # and the instructions are definitely useful enough for a smart compiler to use them in C code (i.e. in memcpy)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3 -mxsave -maes -mpclmul -msha -mrdrnd -mrdseed")
    elseif(SYMCRYPT_TARGET_ARCH MATCHES "X86")
        add_compile_options("-m32")
        add_link_options("-m32")
    elseif(SYMCRYPT_TARGET_ARCH MATCHES "ARM64")
        # Enable a baseline of features for the compiler to support everywhere
        # Assumes that the compiler will not emit crypto instructions as a result of normal C code
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+simd+crypto")
    endif()
    
    # add_compile_options(-Wall)
    # add_compile_options(-Wno-unknown-pragmas)
    add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
    add_compile_options(-g)
    add_compile_options(-Wno-multichar)
    if(SYMCRYPT_PIC)
        add_compile_options(-fPIC)
    endif()
    add_compile_options(-fno-plt)
    add_compile_options(-fno-builtin-bcmp)

    # Required for cross-compiling from AMD64 to ARM64
    # Avoids error: cast from pointer to smaller type 'uintptr_t' when including <memory> from aarch64-linux-gnu
    add_compile_options(-fms-extensions)

    # GCC and clang unroll more aggressively than they should for best performance
    # When we want to unroll loops, we unroll in the source code, so tell the compiler not to unroll
    # (clang seems to respect this option globally, but I could only make GCC behave in AES-GCM by
    # using GCC-specific pragmas for the loops of interest)
    add_compile_options(-fno-unroll-loops)

    # Do not optimize Debug builds
    if (CMAKE_BUILD_TYPE MATCHES Debug)
        add_compile_options(-O0)
    else()
        add_compile_options(-O3)
    endif()

    # In Sanitize version, enable sanitizers
    if (CMAKE_BUILD_TYPE MATCHES Sanitize)
        add_compile_options(-fsanitize=address)
        add_compile_options(-fsanitize=leak)

        # add_compile_options(-fsanitize=undefined)
        # Not using undefined as we do not want to include alignment sanitizer
        add_compile_options(-fsanitize=bool)
        add_compile_options(-fsanitize=builtin)
        add_compile_options(-fsanitize=bounds)
        add_compile_options(-fsanitize=enum)
        add_compile_options(-fsanitize=float-cast-overflow)
        add_compile_options(-fsanitize=float-divide-by-zero)
        add_compile_options(-fsanitize=integer-divide-by-zero)
        add_compile_options(-fsanitize=nonnull-attribute)
        add_compile_options(-fsanitize=pointer-overflow)
        add_compile_options(-fsanitize=return)
        add_compile_options(-fsanitize=returns-nonnull-attribute)
        add_compile_options(-fsanitize=shift)
        add_compile_options(-fsanitize=signed-integer-overflow)
        add_compile_options(-fsanitize=unreachable)
        add_compile_options(-fsanitize=vla-bound)
        add_compile_options(-fsanitize=vptr)
        add_compile_options(-fno-sanitize-recover=all)
        add_link_options(-fsanitize=address)
        add_link_options(-fsanitize=leak)
        add_link_options(-fsanitize=bool)
        add_link_options(-fsanitize=builtin)
        add_link_options(-fsanitize=bounds)
        add_link_options(-fsanitize=enum)
        add_link_options(-fsanitize=float-cast-overflow)
        add_link_options(-fsanitize=float-divide-by-zero)
        add_link_options(-fsanitize=integer-divide-by-zero)
        add_link_options(-fsanitize=nonnull-attribute)
        add_link_options(-fsanitize=pointer-overflow)
        add_link_options(-fsanitize=return)
        add_link_options(-fsanitize=returns-nonnull-attribute)
        add_link_options(-fsanitize=shift)
        add_link_options(-fsanitize=signed-integer-overflow)
        add_link_options(-fsanitize=unreachable)
        add_link_options(-fsanitize=vla-bound)
        add_link_options(-fsanitize=vptr)
        add_link_options(-fno-sanitize-recover=all)
    endif()
else() # Windows

    if(SYMCRYPT_USE_ASM)
        enable_language(ASM_MASM)
    endif()

    add_compile_options(/MP)
    add_compile_options(/Zp8)
    add_compile_options(/guard:cf)
    add_link_options(/guard:cf)
    add_link_options(/dynamicbase)

    # Architecture-specific compiler flags
    if(SYMCRYPT_TARGET_ARCH MATCHES "X86")
        set(CMAKE_GENERATOR_PLATFORM "Win32")
        # We link with modules that use the __stdcall calling convention for X86, but not all of the
        # functions declarations are annotated to specify the calling convention. Thus, we have to
        # set the default to __stdcall.
        add_compile_options(/Gz)
    endif()

    # Remove /RTC1, incompatible with /Ox
    string( REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string( REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    string( REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
    string( REPLACE "/RTC1" "" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
    # /Od incompatible with /Ox
    string( REPLACE "/Od" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string( REPLACE "/Od" "" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    string( REPLACE "/Od" "" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
    string( REPLACE "/Od" "" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

    if(CMAKE_BUILD_TYPE MATCHES Release)
        add_compile_options(/Oxs)
        add_compile_options(/GL)
        add_compile_options(/GF)
        add_compile_options(/Gy)
        add_compile_options(/Gw)
    else()
        if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
            # Prevent error C1128 for AMD64/Debug builds: number of sections exceeded object file format limit
            add_compile_options(/bigobj)
        endif()
    endif()
endif()