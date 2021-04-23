.SUFFIXES: .symcryptasm .cppasm

# We still have architecture-specific inference rules because otherwise we cannot do any architecture-specific preprocessing

# Preprocess amd64 .symcryptasm into masm
{amd64\}.symcryptasm{$(OBJ_PATH)\$(O)\..\amd64\}.asm:
    ..\scripts\symcryptasm_processor.py masm $< $(OBJ_PATH)\$(O)\$(<B).cppasm
    $(CC) $(CFLAGS) /EP /P /I..\inc\ /I.\ /DSYMCRYPT_CPU_AMD64 /DSYMCRYPT_MASM /Fi$@ $(OBJ_PATH)\$(O)\$(<B).cppasm

# Preprocess x86 .cppasm into masm
{i386\}.cppasm{$(OBJ_PATH)\$(O)\..\i386\}.asm:
    $(CC) $(CFLAGS) /EP /P /I..\inc\ /I.\ /DSYMCRYPT_CPU_X86 /DSYMCRYPT_MASM /Fi$@ $<
