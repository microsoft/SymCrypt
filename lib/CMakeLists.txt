set(SOURCES_COMMON
    blockciphermodes.c
    hash.c
    parhash.c
    ccm.c
    ghash.c
    gcm.c
    aes-default.c
    aes-default-bc.c
    aes-key.c
    aes-c.c
    aes-asm.c
    aes-xmm.c
    aes-ymm.c
    aes-neon.c
    aes-selftest.c
    AesTables.c
    aescmac.c
    xtsaes.c
    3des.c
    DesTables.c
    desx.c
    rc2.c
    rc4.c
    sha1.c
    sha256.c
    sha512.c
    md5.c
    md4.c
    md2.c
    hmacmd5.c
    hmacsha1.c
    hmacsha256.c
    hmacsha384.c
    hmacsha512.c
    tlsCbcVerify.c
    aesCtrDrbg.c
    libmain.c
    equal.c
    FatalIntercept.c
    selftest.c
    rdrand.c
    rdseed.c
    sha256Par.c
    sha256Par-ymm.c
    sha512Par.c
    sha512Par-ymm.c
    marvin32.c
    cpuid.c
    cpuid_um.c
    cpuid_notry.c
    pbkdf2.c
    pbkdf2_hmacsha1.c
    pbkdf2_hmacsha256.c
    sp800_108.c
    sp800_108_hmacsha1.c
    sp800_108_hmacsha256.c
    tlsprf.c
    tlsprf_selftest.c
    hkdf.c
    hkdf_selftest.c
    chacha20.c
    poly1305.c
    chacha20_poly1305.c
    a_dispatch.c
    fdef_general.c
    fdef_int.c
    fdef_mod.c
    fdef369_mod.c
    ecpoint.c
    ecurve.c
    eckey.c
    ec_dispatch.c
    ec_short_weierstrass.c
    ec_internal_curves.c
    ec_dsa.c
    ec_dh.c
    ec_montgomery.c
    ec_twisted_edwards.c
    ec_mul.c
    ScsTable.c
    scsTools.c
    primes.c
    modexp.c
    gen_int.c
    crt.c
    rsakey.c
    rsa_enc.c
    rsa_padding.c
    dlgroup.c
    dlkey.c
    dsa.c
    dh.c
    dl_internal_groups.c
    recoding.c
    IEEE802_11SaeCustom.c
  )

function(process_cppasm filepath outformat archdefine)
    get_filename_component(fileextension ${filepath} EXT)
    if(NOT fileextension STREQUAL .cppasm)
        message(FATAL_ERROR "cppasm processing invoked on file with incorrect extension (${filepath} -> ${fileextension})")
    endif()
    if((NOT outformat STREQUAL gas) AND (NOT outformat STREQUAL masm))
        message(FATAL_ERROR "cppasm processing invoked with unrecognized outformat (${outformat})")
    endif()
    if((NOT archdefine STREQUAL amd64) AND (NOT archdefine STREQUAL x86))
        message(FATAL_ERROR "cppasm processing invoked with unrecognized archdefine (${archdefine})")
    endif()
    get_filename_component(rootpath ${filepath} DIRECTORY)
    get_filename_component(filestem ${filepath} NAME_WE) # filestem is the filename w/out extension
    string(TOUPPER ${outformat} outformatupper)
    string(TOUPPER ${archdefine} archdefineupper)
    string(FIND ${rootpath} ${CMAKE_CURRENT_BINARY_DIR} findindex) # check whether input is in the output directory
    if(findindex EQUAL -1) # input in the source directory
        set(filepath ${CMAKE_CURRENT_SOURCE_DIR}/${filepath})
        set(output_pass2 ${CMAKE_CURRENT_BINARY_DIR}/${rootpath}/${filestem}-${outformat}.asm)
    else() # input in the output directory
        set(output_directory ${rootpath})
        set(output_pass2 ${rootpath}/${filestem}.asm)
    endif()

    set(dbg_definition "")
    if(CMAKE_BUILD_TYPE MATCHES Debug)
        set(dbg_definition "-DDBG=1")
    endif()

    if(outformat STREQUAL gas)
        # assume gas => GCC compatible C compiler
        add_custom_command(
            OUTPUT ${output_pass2}
            COMMAND "${CMAKE_C_COMPILER}" -E -P -x c ${filepath} -o ${output_pass2}
                -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/${rootpath} -I${CMAKE_SOURCE_DIR}/inc
                -DSYMCRYPT_${outformatupper} -DSYMCRYPT_CPU_${archdefineupper} ${dbg_definition}
            MAIN_DEPENDENCY ${filepath}
            DEPENDS ${CMAKE_SOURCE_DIR}/inc/C_asm_shared.inc ${filepath} symcryptasm_shared.cppasm
            COMMENT "C preprocessing ${filepath} to ${outformat} (${output_pass2})"
            VERBATIM)
    elseif(outformat STREQUAL masm)
        # assume masm => MSVC C compiler
        add_custom_command(
            OUTPUT ${output_pass2}
            COMMAND "${CMAKE_C_COMPILER}" /EP /P /Fi${output_pass2} ${filepath}
                -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/${rootpath} -I${CMAKE_SOURCE_DIR}/inc
                -DSYMCRYPT_${outformatupper} -DSYMCRYPT_CPU_${archdefineupper} ${dbg_definition}
            MAIN_DEPENDENCY ${filepath}
            DEPENDS ${CMAKE_SOURCE_DIR}/inc/C_asm_shared.inc ${filepath} symcryptasm_shared.cppasm
            COMMENT "C preprocessing ${filepath} to ${outformat} (${output_pass2})"
            VERBATIM)
    endif()
endfunction()

function(process_symcryptasm filepath outformat archdefine)
    get_filename_component(fileextension ${filepath} EXT)
    if(NOT fileextension STREQUAL .symcryptasm)
        message(FATAL_ERROR "symcryptasm processing invoked on file with incorrect extension (${filepath} -> ${fileextension})")
    endif()
    if((NOT outformat STREQUAL gas) AND (NOT outformat STREQUAL masm))
        message(FATAL_ERROR "symcryptasm processing invoked with unrecognized outformat (${outformat})")
    endif()
    get_filename_component(rootpath ${filepath} DIRECTORY)
    get_filename_component(filestem ${filepath} NAME_WE) # filestem is the filename w/out extension
    set(filepath ${CMAKE_CURRENT_SOURCE_DIR}/${filepath})
    set(output_directory ${CMAKE_CURRENT_BINARY_DIR}/${rootpath})
    set(output_cppasm ${output_directory}/${filestem}-${outformat}.cppasm)

    add_custom_command(
        OUTPUT ${output_cppasm}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${output_directory}
        COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/symcryptasm_processor.py ${outformat} ${filepath} ${output_cppasm}
        MAIN_DEPENDENCY ${filepath}
        DEPENDS ${CMAKE_SOURCE_DIR}/scripts/symcryptasm_processor.py
        COMMENT "Python preprocessing ${filepath} to ${outformat} (${output_cppasm})"
        VERBATIM)

    process_cppasm(${output_cppasm} ${outformat} ${archdefine})
endfunction()

if(NOT WIN32)
    list(APPEND SOURCES_COMMON linux/intrinsics.c)
endif()

if(WIN32 AND NOT(SYMCRYPT_TARGET_ENV MATCHES "Generic"))
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        process_symcryptasm(amd64/aesasm.symcryptasm masm amd64)
        process_symcryptasm(amd64/fdef_asm.symcryptasm masm amd64)
        process_symcryptasm(amd64/fdef369_asm.symcryptasm masm amd64)
        process_symcryptasm(amd64/fdef_mulx.symcryptasm masm amd64)
        process_symcryptasm(amd64/wipe.symcryptasm masm amd64)

        list(APPEND SOURCES_COMMON
            amd64/aesasm-masm.asm
            amd64/fdef_asm-masm.asm
            amd64/fdef369_asm-masm.asm
            amd64/fdef_mulx-masm.asm
            amd64/wipe-masm.asm)
        set_source_files_properties(
            amd64/aesasm-masm.asm
            amd64/fdef_asm-masm.asm
            amd64/fdef369_asm-masm.asm
            amd64/fdef_mulx-masm.asm
            amd64/wipe-masm.asm
            PROPERTY LANGUAGE ASM_MASM)

    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86")
        process_cppasm(i386/fdef_asm.cppasm masm x86)

        list(APPEND SOURCES_COMMON
            i386/aesasm.asm
            i386/fdef_asm-masm.asm
            i386/wipe.asm)
        set_source_files_properties(
            i386/aesasm.asm
            i386/fdef_asm-masm.asm
            i386/wipe.asm
            PROPERTY LANGUAGE ASM_MASM)
        set_source_files_properties(
            i386/fdef_asm-masm.asm PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/i386)
    endif()
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        process_symcryptasm(amd64/aesasm.symcryptasm gas amd64)
        process_symcryptasm(amd64/fdef_asm.symcryptasm gas amd64)
        process_symcryptasm(amd64/fdef369_asm.symcryptasm gas amd64)
        process_symcryptasm(amd64/fdef_mulx.symcryptasm gas amd64)
        process_symcryptasm(amd64/wipe.symcryptasm gas amd64)

        list(APPEND SOURCES_COMMON
            amd64/aesasm-gas.asm
            amd64/fdef_asm-gas.asm
            amd64/fdef369_asm-gas.asm
            amd64/fdef_mulx-gas.asm
            amd64/wipe-gas.asm)
        set_source_files_properties(
            amd64/aesasm-gas.asm
            amd64/fdef_asm-gas.asm
            amd64/fdef369_asm-gas.asm
            amd64/fdef_mulx-gas.asm
            amd64/wipe-gas.asm
            PROPERTY LANGUAGE ASM)
    endif()
endif()

if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    set_source_files_properties(aes-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2;-mvaes;-mvpclmulqdq")
    set_source_files_properties(sha256Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
    set_source_files_properties(sha512Par-ymm.c PROPERTIES COMPILE_OPTIONS "-mavx;-mavx2")
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc)

add_library(symcrypt_common STATIC ${SOURCES_COMMON})

if(WIN32)
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

set(SOURCES_GENERIC ${SOURCES_COMMON})
list(APPEND SOURCES_GENERIC env_generic.c)
if(NOT WIN32)
    add_compile_options(-Wno-trigraphs)
endif()
add_library(symcrypt_generic STATIC env_generic.c)
set_target_properties(symcrypt_generic PROPERTIES PREFIX "")
target_link_libraries(symcrypt_generic symcrypt_common)
