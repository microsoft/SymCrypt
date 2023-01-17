set(SOURCES_COMMON
    3des.c
    a_dispatch.c
    aes-asm.c
    aes-c.c
    aes-default-bc.c
    aes-default.c
    aes-key.c
    aes-neon.c
    aes-selftest.c
    aes-xmm.c
    aes-ymm.c
    aescmac.c
    aesCtrDrbg.c
    AesTables.c
    blockciphermodes.c
    ccm.c
    chacha20_poly1305.c
    chacha20.c
    cpuid_notry.c
    cpuid_um.c
    cpuid.c
    crt.c
    DesTables.c
    desx.c
    dh.c
    dl_internal_groups.c
    dlgroup.c
    dlkey.c
    dsa.c
    ec_dh.c
    ec_dispatch.c
    ec_dsa.c
    ec_internal_curves.c
    ec_montgomery.c
    ec_mul.c
    ec_short_weierstrass.c
    ec_twisted_edwards.c
    eckey.c
    ecpoint.c
    ecurve.c
    equal.c
    FatalIntercept.c
    fdef_general.c
    fdef_int.c
    fdef_mod.c
    fdef369_mod.c
    fips_selftest.c
    gcm.c
    gen_int.c
    ghash.c
    hash.c
    hkdf_selftest.c
    hkdf.c
    hmacmd5.c
    hmacsha1.c
    hmacsha256.c
    hmacsha384.c
    hmacsha512.c
    kmac.c
    libmain.c
    marvin32.c
    md2.c
    md4.c
    md5.c
    modexp.c
    paddingPkcs7.c
    parhash.c
    pbkdf2_hmacsha1.c
    pbkdf2_hmacsha256.c
    pbkdf2.c
    poly1305.c
    primes.c
    rc2.c
    rc4.c
    rdrand.c
    rdseed.c
    recoding.c
    rsa_enc.c
    rsa_padding.c
    rsakey.c
    ScsTable.c
    scsTools.c
    selftest.c
    session.c
    sha1.c
    sha256.c
    sha256Par.c
    sha256Par-ymm.c
    sha256-xmm.c
    sha256-ymm.c
    sha512.c
    sha512Par.c
    sha512Par-ymm.c
    sha512-ymm.c
    sha3.c
    sha3_256.c
    sha3_384.c
    sha3_512.c
    shake.c
    sp800_108_hmacsha1.c
    sp800_108_hmacsha256.c
    sp800_108_hmacsha512.c
    sp800_108.c
    srtp_kdf.c
    srtp_kdf_selftest.c
    ssh_kdf.c
    ssh_kdf_sha256.c
    ssh_kdf_sha512.c
    tlsCbcVerify.c
    tlsprf_selftest.c
    tlsprf.c
    xtsaes.c
  )

function(process_cppasm filepath outformat archdefine)
    get_filename_component(fileextension ${filepath} EXT)
    if(NOT fileextension STREQUAL .cppasm)
        message(FATAL_ERROR "cppasm processing invoked on file with incorrect extension (${filepath} -> ${fileextension})")
    endif()
    if((NOT outformat STREQUAL gas) AND (NOT outformat STREQUAL masm))
        message(FATAL_ERROR "cppasm processing invoked with unrecognized outformat (${outformat})")
    endif()
    if((NOT archdefine STREQUAL amd64) AND (NOT archdefine STREQUAL x86) AND (NOT archdefine STREQUAL arm64))
        message(FATAL_ERROR "cppasm processing invoked with unrecognized archdefine (${archdefine})")
    endif()
    get_filename_component(rootpath ${filepath} DIRECTORY)
    get_filename_component(filestem ${filepath} NAME_WE) # filestem is the filename w/out extension
    string(TOUPPER ${outformat} outformatupper)
    string(TOUPPER ${archdefine} archdefineupper)
    string(FIND ${rootpath} ${CMAKE_CURRENT_BINARY_DIR} findindex) # check whether input is in the output directory
    if(findindex EQUAL -1) # input in the source directory
        set(filepath ${CMAKE_CURRENT_SOURCE_DIR}/${filepath})
        set(output_asm ${CMAKE_CURRENT_BINARY_DIR}/${rootpath}/${filestem}-${outformat}.asm)
    else() # input in the output directory
        set(output_directory ${rootpath})
        set(output_asm ${rootpath}/${filestem}.asm)
    endif()

    set(dbg_definition "")
    if(CMAKE_BUILD_TYPE MATCHES "Debug|Sanitize")
        set(dbg_definition "-DDBG=1")
    endif()

    if(outformat STREQUAL gas)
        # assume gas => GCC compatible C compiler
        add_custom_command(
            OUTPUT ${output_asm}
            COMMAND "${CMAKE_C_COMPILER}" -E -P -x c ${filepath} -o ${output_asm}
                -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/${rootpath} -I${CMAKE_SOURCE_DIR}/inc
                -DSYMCRYPT_${outformatupper} -DSYMCRYPT_CPU_${archdefineupper} ${dbg_definition}
            MAIN_DEPENDENCY ${filepath}
            DEPENDS ${CMAKE_SOURCE_DIR}/inc/C_asm_shared.inc ${filepath} symcryptasm_shared.cppasm
            COMMENT "C preprocessing ${filepath} to ${outformat} (${output_asm})"
            VERBATIM)
    elseif(outformat STREQUAL masm)
        # assume masm => MSVC C compiler
        add_custom_command(
            OUTPUT ${output_asm}
            COMMAND "${CMAKE_C_COMPILER}" /EP /P /Fi${output_asm} ${filepath}
                -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/${rootpath} -I${CMAKE_SOURCE_DIR}/inc
                -DSYMCRYPT_${outformatupper} -DSYMCRYPT_CPU_${archdefineupper} ${dbg_definition}
            MAIN_DEPENDENCY ${filepath}
            DEPENDS ${CMAKE_SOURCE_DIR}/inc/C_asm_shared.inc ${filepath} symcryptasm_shared.cppasm
            COMMENT "C preprocessing ${filepath} to ${outformat} (${output_asm})"
            VERBATIM)
    endif()
endfunction()

function(process_symcryptasm filepath outformat archdefine callingconvention)
    get_filename_component(fileextension ${filepath} EXT)
    if(NOT fileextension STREQUAL .symcryptasm)
        message(FATAL_ERROR "symcryptasm processing invoked on file with incorrect extension (${filepath} -> ${fileextension})")
    endif()
    if((NOT outformat STREQUAL gas) AND (NOT outformat STREQUAL masm) AND (NOT outformat STREQUAL armasm64))
        message(FATAL_ERROR "symcryptasm processing invoked with unrecognized outformat (${outformat})")
    endif()
    if((NOT archdefine STREQUAL amd64) AND (NOT archdefine STREQUAL x86) AND (NOT archdefine STREQUAL arm64))
        message(FATAL_ERROR "symcryptasm processing invoked with unrecognized archdefine (${archdefine})")
    endif()
    if((NOT callingconvention STREQUAL msft) AND (NOT callingconvention STREQUAL systemv) AND (NOT callingconvention STREQUAL aapcs64) AND (NOT callingconvention STREQUAL arm64ec))
        message(FATAL_ERROR "symcryptasm processing invoked with unrecognized callingconvention (${callingconvention})")
    endif()
    get_filename_component(rootpath ${filepath} DIRECTORY)
    get_filename_component(filestem ${filepath} NAME_WE) # filestem is the filename w/out extension
    set(filepath ${CMAKE_CURRENT_SOURCE_DIR}/${filepath})
    set(output_directory ${CMAKE_CURRENT_BINARY_DIR}/${rootpath})
    set(output_cppasm ${output_directory}/${filestem}-${outformat}.cppasm)

    add_custom_command(
        OUTPUT ${output_cppasm}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${output_directory}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/symcryptasm_processor.py ${outformat} ${archdefine} ${callingconvention} ${filepath} ${output_cppasm}
        MAIN_DEPENDENCY ${filepath}
        DEPENDS ${CMAKE_SOURCE_DIR}/scripts/symcryptasm_processor.py
        COMMENT "Python preprocessing ${filepath} to ${outformat} (${output_cppasm})"
        VERBATIM)

    process_cppasm(${output_cppasm} ${outformat} ${archdefine})
endfunction()

if(WIN32)
    list(APPEND SOURCES_COMMON IEEE802_11SaeCustom.c)
else()
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        list(APPEND SOURCES_COMMON linux/intrinsics.c)
    endif()
endif()

if(WIN32 AND SYMCRYPT_USE_ASM)
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        process_symcryptasm(amd64/aesasm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/fdef_asm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/fdef369_asm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/fdef_mulx.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/wipe.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/sha256xmm_asm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/sha256ymm_asm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/sha512ymm_asm.symcryptasm masm amd64 msft)
        process_symcryptasm(amd64/sha512ymm_avx512vl_asm.symcryptasm masm amd64 msft)

        list(APPEND SOURCES_COMMON
            amd64/aesasm-masm.asm
            amd64/fdef_asm-masm.asm
            amd64/fdef369_asm-masm.asm
            amd64/fdef_mulx-masm.asm
            amd64/wipe-masm.asm
            amd64/sha256xmm_asm-masm.asm            
            amd64/sha256ymm_asm-masm.asm            
            amd64/sha512ymm_asm-masm.asm
            amd64/sha512ymm_avx512vl_asm-masm.asm)
        set_source_files_properties(
            amd64/aesasm-masm.asm
            amd64/fdef_asm-masm.asm
            amd64/fdef369_asm-masm.asm
            amd64/fdef_mulx-masm.asm
            amd64/wipe-masm.asm
            amd64/sha256xmm_asm-masm.asm            
            amd64/sha256ymm_asm-masm.asm            
            amd64/sha512ymm_asm-masm.asm
            amd64/sha512ymm_avx512vl_asm-masm.asm
            PROPERTY LANGUAGE ASM_MASM)

    elseif(SYMCRYPT_TARGET_ARCH MATCHES "X86")
        process_cppasm(i386/aesasm.cppasm masm x86)
        process_cppasm(i386/fdef_asm.cppasm masm x86)

        list(APPEND SOURCES_COMMON
            i386/aesasm-masm.asm
            i386/fdef_asm-masm.asm
            i386/wipe.asm)
        set_source_files_properties(
            i386/aesasm-masm.asm
            i386/fdef_asm-masm.asm
            i386/wipe.asm
            PROPERTY LANGUAGE ASM_MASM)
        set_source_files_properties(
            i386/fdef_asm-masm.asm PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/i386)
    endif()
elseif(SYMCRYPT_USE_ASM) # Linux
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        process_symcryptasm(amd64/aesasm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/fdef_asm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/fdef369_asm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/fdef_mulx.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/wipe.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/sha256xmm_asm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/sha256ymm_asm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/sha512ymm_asm.symcryptasm gas amd64 systemv)
        process_symcryptasm(amd64/sha512ymm_avx512vl_asm.symcryptasm gas amd64 systemv)

        list(APPEND SOURCES_COMMON
            amd64/aesasm-gas.asm
            amd64/fdef_asm-gas.asm
            amd64/fdef369_asm-gas.asm
            amd64/fdef_mulx-gas.asm
            amd64/wipe-gas.asm
            amd64/sha256xmm_asm-gas.asm
            amd64/sha256ymm_asm-gas.asm
            amd64/sha512ymm_asm-gas.asm
            amd64/sha512ymm_avx512vl_asm-gas.asm)
        set_source_files_properties(
            amd64/aesasm-gas.asm
            amd64/fdef_asm-gas.asm
            amd64/fdef369_asm-gas.asm
            amd64/fdef_mulx-gas.asm
            amd64/wipe-gas.asm
            amd64/sha256xmm_asm-gas.asm
            amd64/sha256ymm_asm-gas.asm
            amd64/sha512ymm_asm-gas.asm
            amd64/sha512ymm_avx512vl_asm-gas.asm
            PROPERTY LANGUAGE ASM)
    elseif(SYMCRYPT_TARGET_ARCH MATCHES "ARM64")
        process_symcryptasm(arm64/fdef_asm.symcryptasm gas arm64 aapcs64)
        process_symcryptasm(arm64/fdef369_asm.symcryptasm gas arm64 aapcs64)
        process_symcryptasm(arm64/wipe.symcryptasm gas arm64 aapcs64)

        list(APPEND SOURCES_COMMON
            arm64/fdef_asm-gas.asm
            arm64/fdef369_asm-gas.asm
            arm64/wipe-gas.asm)
        set_source_files_properties(
            arm64/fdef_asm-gas.asm
            arm64/fdef369_asm-gas.asm
            arm64/wipe-gas.asm
            PROPERTY LANGUAGE ASM)
    endif()
endif()

if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
    if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        set_source_files_properties(aes-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mvaes;-mvpclmulqdq")
        set_source_files_properties(sha256Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
        set_source_files_properties(sha512Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
        set_source_files_properties(sha256-xmm.c PROPERTIES COMPILE_OPTIONS "-mssse3")
        set_source_files_properties(sha256-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
        set_source_files_properties(sha512-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mbmi2")
    endif()
endif()

if(WIN32)
    # Disable run-time type information for SymCrypt library - we do not use it
    add_compile_options(/GR-)

    add_library(symcrypt_usermodewin7 STATIC env_windowsUserModeWin7.c)
    set_target_properties(symcrypt_usermodewin7 PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_usermodewin7 symcrypt_common)

    add_library(symcrypt_usermodewin8_1 STATIC env_windowsUserModeWin8_1.c)
    set_target_properties(symcrypt_usermodewin8_1 PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_usermodewin8_1 symcrypt_common)

    # add_library(symcrypt_kernelmodewin7 STATIC env_windowsKernelModeWin7.c)
    # set_target_properties(symcrypt_kernelmodewin7 PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_kernelmodewin7 symcrypt_common)

    # add_library(symcrypt_kernelmodewin8_1 STATIC env_windowsKernelModeWin8_1.c)
    # set_target_properties(symcrypt_kernelmodewin8_1 PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_kernelmodewin8_1 symcrypt_common)

    # add_library(symcrypt_windowsbootlib STATIC env_windowsBootLib.c)
    # set_target_properties(symcrypt_windowsbootlib PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_windowsbootlib symcrypt_common)

    add_library(symcrypt_windowskerneldebugger STATIC env_windowsKernelDebugger.c)
    set_target_properties(symcrypt_windowskerneldebugger PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_windowskerneldebugger symcrypt_common)

    add_library(symcrypt_windows10sgx STATIC env_win10Sgx.c)
    set_target_properties(symcrypt_windows10sgx PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_windows10sgx symcrypt_common)
endif()

if(NOT WIN32)
    add_compile_options(-Wno-trigraphs)

    if (SYMCRYPT_STACK_PROTECTION)
        # Mitigate stack buffer overruns, and stack clash attacks
        add_compile_options(-fstack-protector-strong)
        add_compile_options(-Wstack-protector)
        add_compile_options(--param ssp-buffer-size=4)

        if(CMAKE_C_COMPILER_ID MATCHES "GNU")
            add_compile_options(-fstack-clash-protection)
        endif()
    endif()

    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64|X86")
        if (CMAKE_C_COMPILER_ID MATCHES "Clang")
            add_compile_options(-mllvm -x86-speculative-load-hardening)
        endif()
    endif()

    add_library(symcrypt_linuxusermode STATIC env_linuxUserMode.c)
    set_target_properties(symcrypt_linuxusermode PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_linuxusermode symcrypt_common)
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc)

add_library(symcrypt_common STATIC ${SOURCES_COMMON})

add_library(symcrypt_generic STATIC env_generic.c)
set_target_properties(symcrypt_generic PROPERTIES PREFIX "")
target_link_libraries(symcrypt_generic symcrypt_common)
