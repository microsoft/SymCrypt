@echo on

set TmpBuildInfoFile=%temp%\symcrypt-build-tmp.txt
set TmpBuildStringFile=%temp%\symcrypt-build-string.txt

@rem We'll probably rename the version numbers to the new definition
call :GetVersionNumber SYMCRYPT_CODE_VERSION_API MajorVersionNumber

call :GetVersionNumber SYMCRYPT_CODE_VERSION_MINOR MinorVersionNumber

call :GetBranchName BranchName

call :GetDateTime DateTime

call :GetCommitInfo CommitInfo

echo // Build information. WARNING: automatically generated; DO NOT EDIT > %TmpBuildInfoFile%
echo #define SYMCRYPT_BUILD_INFO_BRANCH    "%BranchName%" >> %TmpBuildInfoFile%
echo #define SYMCRYPT_BUILD_INFO_COMMIT    "%CommitInfo%" >> %TmpBuildInfoFile%
echo #define SYMCRYPT_BUILD_INFO_VERSION   "%MajorVersionNumber%.%MinorVersionNumber%" >> %TmpBuildInfoFile%
echo #define SYMCRYPT_BUILD_INFO_TIMESTAMP "%DateTime%" >> %TmpBuildInfoFile%

copy %TmpBuildInfoFile% %OBJECT_ROOT%\SymCrypt\build\%O%\buildInfo.h

type %TmpBuildInfoFile%

goto cleanup

:GetCommitInfo
git log -n 1 --date=iso-strict-local --format=%%cd_%%h >%TmpBuildStringFile%
set /p %1=<%TmpBuildStringFile%
goto :EOF


:GetDateTime
set %1=%date:~-4%-%date:~-10,2%-%date:~-7,2%T%time:~,-3%
goto :EOF

:GetBranchName
git symbolic-ref --short HEAD >%TmpBuildStringFile%
set /p %1=<%TmpBuildStringFile%
goto :EOF

:GetVersionNumber
@rem argument: symbol name
@rem get into variable VersionNumber

@rem Extract the #define line from the version file
findstr define %SDXROOT%\SymCrypt\inc\symcrypt_internal_shared.inc | findstr %1 >%TmpBuildStringFile%
set /p T=<%TmpBuildStringFile%

@rem Extract the last item
for /f "tokens=3" %%i in ("%T%") do set %2=%%i

goto :EOF




:cleanup

set T=
set MajorVersionNumber=
set MinorVersionNumber=
set BranchName=
set DateTime=
set CommitInfo=
del %TmpBuildStringFile%
del %TmpBuildInfoFile%