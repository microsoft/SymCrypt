rem 
rem First stage of SymCrypt build process
rem Copyright (c) Microsoft Corporation. Licensed under the MIT license.
rem


rem @echo off
cd scbuild
call build -c -z
cd ..

rem Currently the build errors because of OACR issues
if ERRORLEVEL 1 goto :BuildError

rem We make a copy of the binary so that the later build can remove the binary in the OBJ dir.

rem
rem We have to construct the directory name where the resulting binary can be found
rem
if /I "%_BuildArch%" ==  "x86" (
	set ScBuildTmp=i386
) ELSE ( 
	set ScBuildTmp=%_BuildArch%
)

rem
rem We delete the temp copy to ensure we never run an old version.
rem (The copy might fail if the exe directory changes for some reason.)
rem
del %TEMP%\scbuild.exe 2>nul
copy %OBJECT_ROOT%\symcrypt\scbuild\obj%_BuildType%\%ScBuildTmp%\scbuild.exe %TEMP%\scbuild.exe
set ScBuildTmp=

echo on
%TEMP%\scbuild.exe %*
@echo off
del %TEMP%\scbuild.exe

@goto :EOF


:BuildError
rem cd ..
echo Error in build, aborting scbuild.cmd script...
goto :EOF
