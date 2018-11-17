TARGETTYPE=PROGRAM

MSC_WARNING_LEVEL=/W4 /WX
#MSC_OPTIMIZATION=/Ox /Oi /Fa		# /Fa generates ASM listing files.

UMTYPE=console

# mark this as test code, as that re-enabled the __DATE__ and __TIME__ macros in the compiler.
TEST_CODE= 1

# TEST_CODE disables LTCG, this re-enables it
LINK_TIME_CODE_GENERATION = 1

INCLUDES= \
#    ..\..\..\released\windows\ntrsa32\inc; \
#    ..\..\..\released\windows\bignum; \
    $(BASEDIR)\onecore\ds\security\cryptoapi\inc\cryptolegacy; \
    $(DS_INC_PATH);                 \
    $(DS_INC_PATH)\crypto; \
    $(ONECOREDS_INC_PATH)\crypto; \
    $(ONECOREDS_PRIVATE_INC_PATH_L)\crypto; \
#    $(ONECORE_PRIVATE_PATH)\ds\inc\crypto; \
    ..\..\inc ; \
    ..\inc ; \
    ..\lib ; \
    $(DDK_INC_PATH); \

SOURCES= \
    main_exe.cpp \
    symcryptunittest.rc \
        
#
# We link RSA32 and msbignum twice, once from the Enigma build location, and once from windows.
# This works in either state.
#
TARGETLIBS= \
#    $(MINCORE_SDK_LIB_PATH)\mincore.lib \
    $(MINWIN_SDK_LIB_PATH)\ntdll.lib \
!if EXIST( $(PROJECT_OBJ_ROOT)\released\windows\ntrsa32\umode\$(O)\rsa32.lib )
    $(PROJECT_OBJ_ROOT)\released\windows\ntrsa32\umode\$(O)\rsa32.lib \
!endif
    $(DS_LIB_PATH)\rsa32.lib \
!if EXIST( $(PROJECT_OBJ_ROOT)\released\windows\bignum\winnt\$(O)\msbignum.lib )
    $(PROJECT_OBJ_ROOT)\released\windows\bignum\winnt\$(O)\msbignum.lib \
!endif
    $(ONECOREDS_LIB_PATH)\msbignum.lib \
    $(SDK_LIB_PATH)\powrprof.lib \
    $(SDK_LIB_PATH)\bcrypt.lib \
#***** REMOVE NEXT LINE BEFORE SHIP *****
    $(MINWIN_PRIV_SDK_LIB_PATH)\symcrypt-$(BUILD_TYPE).lib \
    $(OBJECT_ROOT)\symcrypt\lib\$(O)\symcrypt.lib \
    $(OBJECT_ROOT)\symcrypt\unittest\lib\$(O)\symcryptunittest_lib.lib \
	

UNICODE = 1

USE_MSVCRT=1

BUFFER_OVERFLOW_CHECKS=1

ENABLE_ISO_VOLATILE_WARNING=1 

PRECOMPILED_INCLUDE = precomp.h
PRECOMPILED_CXX = 1
USE_RTTI = 1

#NT_SIGNCODE = 1

USE_STL = 1
STL_VER = 70
USE_NATIVE_EH = 1

MUI = 0
MUI_COMMENT = Unittest only, this is never localized

TRACER_ENABLED = 0

