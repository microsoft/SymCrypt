set(SOURCES
    rng.c
    module_opteeTa.c
    ../common/nointegrity.c
    ../common/callbacks_singlethreaded.c)

include_directories(../common)

# Build SymCrypt lib for OPTEE
add_library(symcrypt_optee STATIC ${SOURCES} $<TARGET_OBJECTS:symcrypt_envOpteeTa> $<TARGET_OBJECTS:symcrypt_common> $<TARGET_OBJECTS:symcrypt_module_linux_common>)