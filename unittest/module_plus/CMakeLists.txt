# CMakeLists.txt for symcrypt_plus_testmodule - see README.md for design rationale.
#
# Target-agnostic: symcrypt_plus_testmodule.dll on Windows (combined exports.def),
# libsymcrypt_plus_testmodule.so/.dylib on POSIX (generated export map + dynamic
# dependency against the production libsymcrypt module).

# Skip if the base SymCrypt module target we wrap isn't configured for this
# preset (Sanitize, OPTEE-only, external CMake setups, etc.).
if(WIN32)
    if(NOT TARGET symcrypttestmodule)
        message(STATUS "symcrypt_plus_testmodule: skipped (symcrypttestmodule target not configured)")
        return()
    endif()
else()
    if(NOT TARGET symcrypt_generic_posix)
        message(STATUS "symcrypt_plus_testmodule: skipped (symcrypt_generic_posix target not configured)")
        return()
    endif()
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(SOURCES module_plus.cpp)
set(GENERATED_EXPORT_DIR ${CMAKE_BINARY_DIR}/generated)
set(LOCAL_EXPORTS_DEF ${CMAKE_CURRENT_SOURCE_DIR}/exports_plus_local.def)

if(WIN32)
    # Generated DEF forwards every base SymCrypt export to symcrypttestmodule
    # so SCTEST_LOOKUP_DYNSYM can resolve HPKE + base symbols via one handle.
    set(GENERATED_DEF ${GENERATED_EXPORT_DIR}/exports_plus.def)
    add_custom_command(
        OUTPUT  ${GENERATED_DEF}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${GENERATED_EXPORT_DIR}
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/gen_combined_def.py
                --base   ${SYMCRYPT_SOURCE_DIR}/unittest/module_windows/exports.def
                --local ${LOCAL_EXPORTS_DEF}
                --out    ${GENERATED_DEF}
        DEPENDS ${SYMCRYPT_SOURCE_DIR}/unittest/module_windows/exports.def
                ${LOCAL_EXPORTS_DEF}
                ${CMAKE_CURRENT_SOURCE_DIR}/gen_combined_def.py
        COMMENT "Generating exports_plus.def"
        VERBATIM)

    list(APPEND SOURCES ${GENERATED_DEF})
endif()

add_library(symcrypt_plus_testmodule SHARED ${SOURCES})

target_include_directories(symcrypt_plus_testmodule PRIVATE
    ${SYMCRYPT_SOURCE_DIR}/inc
    ${SYMCRYPT_SOURCE_DIR}/inc/symcrypt_plus
)

if(WIN32)
    target_link_libraries(symcrypt_plus_testmodule
        symcrypt_plus
        symcrypttestmodule
        bcrypt
    )

    add_dependencies(symcrypt_plus_testmodule symcrypttestmodule)

    # Co-locate with symcrypttestmodule.dll so its loader can find it.
    set_target_properties(symcrypt_plus_testmodule PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
    )
else()
    set(GENERATED_EXPORTS_VER ${GENERATED_EXPORT_DIR}/exports_plus.ver)
    set(GENERATED_EXPORTS_OSX ${GENERATED_EXPORT_DIR}/exports_plus.osx)
    add_custom_command(
        OUTPUT ${GENERATED_EXPORTS_VER} ${GENERATED_EXPORTS_OSX}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${GENERATED_EXPORT_DIR}
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/gen_combined_def.py
                --local ${LOCAL_EXPORTS_DEF}
                --out-ver ${GENERATED_EXPORTS_VER}
                --out-osx ${GENERATED_EXPORTS_OSX}
        DEPENDS ${LOCAL_EXPORTS_DEF}
                ${CMAKE_CURRENT_SOURCE_DIR}/gen_combined_def.py
        COMMENT "Generating POSIX exports for symcrypt_plus_testmodule"
        VERBATIM)
    add_custom_target(symcrypt_plus_testmodule_exports
        DEPENDS ${GENERATED_EXPORTS_VER} ${GENERATED_EXPORTS_OSX})

    # Link against symcrypt_generic_posix to inherit the dynamic libsymcrypt
    # dependency; libdl for SymCryptModuleInit's dlopen/dlsym; pthread for
    # mutex callbacks.
    #
    # symcrypt_plus is a static archive and nothing here references HPKE, so
    # force-loading is needed to keep the exports listed in the export map.
    target_link_libraries(symcrypt_plus_testmodule PRIVATE
        symcrypt_generic_posix
        pthread
        ${CMAKE_DL_LIBS}
    )

    add_dependencies(symcrypt_plus_testmodule
        symcrypt_generic_posix
        symcrypt_plus
        symcrypt_plus_testmodule_exports)

    if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        target_link_options(symcrypt_plus_testmodule PRIVATE
            "-Wl,-force_load,$<TARGET_FILE:symcrypt_plus>"
            "-Wl,-exported_symbols_list,${GENERATED_EXPORTS_OSX}"
        )
        set(SYMCRYPT_PLUS_TESTMODULE_RPATH "@loader_path;@loader_path/../lib")
    else()
        target_link_options(symcrypt_plus_testmodule PRIVATE
            "-Wl,--whole-archive"
            "$<TARGET_FILE:symcrypt_plus>"
            "-Wl,--no-whole-archive"
            "-Wl,--version-script=${GENERATED_EXPORTS_VER}"
            "-Wl,-z,now"
            "-Wl,-z,relro"
            "-Wl,-z,noexecstack"
        )
        set(SYMCRYPT_PLUS_TESTMODULE_RPATH "$ORIGIN:$ORIGIN/../lib")
    endif()

    # RPATH covers both layouts: packaged module in test/, libsymcrypt in lib/
    # uses ../lib; co-located module dropped next to libsymcrypt uses the module
    # directory. BUILD_WITH_INSTALL_RPATH prevents CMake from auto-appending the
    # absolute build-host link directory (which would ship in the package).
    set_target_properties(symcrypt_plus_testmodule PROPERTIES
        BUILD_RPATH              "${SYMCRYPT_PLUS_TESTMODULE_RPATH}"
        INSTALL_RPATH            "${SYMCRYPT_PLUS_TESTMODULE_RPATH}"
        BUILD_WITH_INSTALL_RPATH TRUE
    )

    # Build-tree convenience: symlink the base module's libsymcrypt.so.<API>
    # next to the plus module so the co-located RPATH resolves it without
    # LD_LIBRARY_PATH/DYLD_LIBRARY_PATH. Not shipped; the package uses ../lib.
    add_custom_command(TARGET symcrypt_plus_testmodule POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E create_symlink
                generic/$<TARGET_SONAME_FILE_NAME:symcrypt_generic_posix>
                $<TARGET_FILE_DIR:symcrypt_plus_testmodule>/$<TARGET_SONAME_FILE_NAME:symcrypt_generic_posix>
        COMMENT "Symlinking $<TARGET_SONAME_FILE_NAME:symcrypt_generic_posix> next to symcrypt_plus_testmodule for $ORIGIN-based dlopen in build tree"
        VERBATIM
    )
endif()
