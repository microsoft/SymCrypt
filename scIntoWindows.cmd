set ScTempDir=%TEMP%\SymCryptIntoWindowsTemp

@IF /I "%1" EQU "" (
@echo Usage ScIntoWindows CABfile [noRefCopy]
goto error
)

@if NOT EXIST %1 (
echo Could not find file %1
goto error
)

@if /I "%~x1" NEQ ".CAB" (
echo Not a CAB file: %1
goto error
)

if EXIST %ScTempDir% (
    rd /s /q %ScTempDir%
    @if ERRORLEVEL 1 (
    echo rd failed
    goto error
    )
)

md %ScTempDir%
@if ERRORLEVEL 1 (
echo md failed
goto error
)

copy %1 %ScTempDir%
extract /L %ScTempDir% %1 *.*
@if ERRORLEVEL 1 (
echo Extract failed
goto error
)

pushd %SDXROOT%\minio\published
@if ERRORLEVEL 1 (
echo Pushd failed
goto error
)

for %%a in (amd64chk amd64fre armchk armfre x86chk x86fre arm64chk arm64fre) do (
	copy %ScTempDir%\lib\%%a\symcrypt.lib lib\%%a\SymCrypt.w
	@if ERRORLEVEL 1 (
	echo Copy failed
	goto error
	)
)

copy %ScTempDir%\inc\symcrypt.h inc\ds\symcrypt.w
@if ERRORLEVEL 1 (
echo Copy failed
goto error
)
copy %ScTempDir%\inc\symcrypt_low_level.h inc\ds\symcrypt_low_level.w
@if ERRORLEVEL 1 (
echo Copy failed
goto error
)
copy %ScTempDir%\inc\symcrypt_internal.h inc\ds\symcrypt_internal.w
@if ERRORLEVEL 1 (
echo Copy failed
goto error
)
copy %ScTempDir%\inc\symcrypt_internal_shared.inc inc\ds\symcrypt_internal_shared.inc
@if ERRORLEVEL 1 (
echo Copy failed
goto error
)

popd
pushd %SDXROOT%\onecore\ds\security\cryptoapi\ncrypt\test\unittest
@if ERRORLEVEL 1 (
echo Pushd to DSTEST failed
goto error
)

for %%a in (amd64chk amd64fre armchk armfre x86chk x86fre arm64fre arm64chk) do (
	copy %ScTempDir%\lib\%%a\symcryptunittest.exe %%a\symcryptunittest.exx
	@if ERRORLEVEL 1 (
	echo Copy failed
	goto error
	)
	copy %ScTempDir%\lib\%%a\symcrypttestmodule.dll %%a\symcrypttestmodule.dlx
	@if ERRORLEVEL 1 (
	echo Copy failed
	goto error
	)
)

for %%a in (amd64chk amd64fre arm64fre arm64chk) do (
	copy %ScTempDir%\lib\%%a\SymCryptKernelTestModule_UM.dll %%a\symcryptkerneltestmodule_um.dlx
	@if ERRORLEVEL 1 (
	echo Copy failed
	goto error
	)
	copy %ScTempDir%\lib\%%a\SymCryptKernelTestModule.sys %%a\symcryptkerneltestmodule.syx
	@if ERRORLEVEL 1 (
	echo Copy failed
	goto error
	)
)

popd


@IF /I "%2" NEQ "" (
goto noRefCopy
)

set ScReferenceCopy=\\fsu\shares\SymCrypt\SymCrypt_Windows_Latest
set ScCabCopy=\\fsu\shares\SymCrypt\SymCryptCabs

copy %1 %ScCabCopy%

rd /s /q %ScReferenceCopy%

robocopy %scTempDir% %ScReferenceCopy% /s
@if ERRORLEVEL 2 (
echo RoboCopy failed
goto error
)
attrib +r %ScReferenceCopy%\*.* /s
@if ERRORLEVEL 1 (
echo Attrib failed to make reference copy read-only
goto error
)

:noRefCopy

@echo ---------------- Success! ---------------------
@goto done

:error
@echo **************** ERROR! ***********************

:done
@set ScTempDir=
@set ScReferenceCopy=
@set ScCabCopy=
