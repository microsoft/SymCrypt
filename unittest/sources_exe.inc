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
    ..\inc; \
    ..\..\inc; \
    ..\lib; \
    $(OBJECT_ROOT)\SymCrypt\Publics\$(O); \
    $(ONECOREDS_INTERNAL_INC_PATH_L)\crypto; \
    $(DDK_INC_PATH); \

SOURCES= \
    main_exe.cpp \
    symcryptunittest.rc \
        
TARGETLIBS= \
#    $(MINCORE_SDK_LIB_PATH)\mincore.lib \
    $(MINWIN_EXTERNAL_SDK_LIB_PATH_L)\ntdll.lib \
    $(OBJECT_ROOT)\SymCrypt\Publics\$(O)\rsa32.lib \
    $(OBJECT_ROOT)\SymCrypt\Publics\$(O)\msbignum.lib \
    $(ONECORE_EXTERNAL_SDK_LIB_PATH)\powrprof.lib \
    $(ONECORE_EXTERNAL_SDK_LIB_PATH)\bcrypt.lib \
    $(OBJECT_ROOT)\symcrypt\lib\$(O)\symcrypt.lib \
    $(OBJECT_ROOT)\symcrypt\unittest\lib\$(O)\symcryptunittest_lib.lib \
	

UNICODE = 1

USE_MSVCRT=1
USE_UNICRT=1

BUFFER_OVERFLOW_CHECKS=1

ENABLE_ISO_VOLATILE_WARNING=1 

PRECOMPILED_INCLUDE = precomp.h
PRECOMPILED_CXX = 1
USE_RTTI = 1

#NT_SIGNCODE = 1

USE_STL = 1
STL_VER = STL_VER_CURRENT
USE_NATIVE_EH = 1

MUI = 0
MUI_COMMENT = Unittest only, this is never localized

TRACER_ENABLED = 0

