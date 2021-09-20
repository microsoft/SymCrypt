.SUFFIXES: .symcryptasm .cppasm

# We still have architecture-specific inference rules because otherwise we cannot do any architecture-specific preprocessing

# Preprocess amd64 .symcryptasm into masm
{amd64\}.symcryptasm{$(OBJ_PATH)\$(O)\..\amd64\}.asm:
    ..\scripts\symcryptasm_processor.py masm amd64 msft $< $(OBJ_PATH)\$(O)\$(<B).cppasm
    $(CC) $(CFLAGS) /EP /P /I..\inc\ /I.\ /DSYMCRYPT_CPU_AMD64 /DSYMCRYPT_MASM /Fi$@ $(OBJ_PATH)\$(O)\$(<B).cppasm

# Preprocess x86 .cppasm into masm
{i386\}.cppasm{$(OBJ_PATH)\$(O)\..\i386\}.asm:
    $(CC) $(CFLAGS) /EP /P /I..\inc\ /I.\ /DSYMCRYPT_CPU_X86 /DSYMCRYPT_MASM /Fi$@ $<


# Preprocess arm64 .symcryptasm into masm
{arm64\}.symcryptasm{$(OBJ_PATH)\$(O)\..\arm64\}.asm:
    ..\scripts\symcryptasm_processor.py armasm64 arm64 aapcs64 $< $(OBJ_PATH)\$(O)\$(<B).asm

# Preprocess arm64ec .symcryptasm into masm
{arm64\}.symcryptasm{$(OBJ_PATH)\$(O)\..\arm64\arm64ec\}.asm:
    ..\scripts\symcryptasm_processor.py armasm64 arm64 arm64ec $< $(OBJ_PATH)\$(O)\arm64ec\$(<B).asm
