@echo on

@rem We'll probably rename the version numbers to the new definition
call :GetVersionNumber SYMCRYPT_CODE_VERSION_API MajorVersionNumber

call :GetVersionNumber SYMCRYPT_CODE_VERSION_MINOR MinorVersionNumber

call :GetBranchName BranchName

call :GetDateTime DateTime

call :GetCommitInfo CommitInfo

echo // Build information. WARNING: automatically generated; DO NOT EDIT >tmp.txt
echo #define SYMCRYPT_BUILD_INFO_BRANCH    "%BranchName%" >>tmp.txt
echo #define SYMCRYPT_BUILD_INFO_COMMIT    "%CommitInfo%" >>tmp.txt
echo #define SYMCRYPT_BUILD_INFO_VERSION   "%MajorVersionNumber%.%MinorVersionNumber%" >> tmp.txt
echo #define SYMCRYPT_BUILD_INFO_TIMESTAMP "%DateTime%" >>tmp.txt

copy tmp.txt %OBJECT_ROOT%\SymCrypt\build\%O%\buildInfo.h

type tmp.txt

goto cleanup

:GetCommitInfo
git log -n 1 --date=iso-strict-local --format=%%cd_%%h >t.txt
set /p %1=<t.txt
goto :EOF


:GetDateTime
set %1=%date:~-4%-%date:~-10,2%-%date:~-7,2%T%time:~,-3%
goto :EOF

:GetBranchName
git status | findstr /C:"On branch" >t.txt
set /P T=<t.txt
for /f "tokens=3" %%i in ("%T%") do set %1=%%i
goto :EOF

:GetVersionNumber
@rem argument: symbol name
@rem get into variable VersionNumber

@rem Extract the #define line from the version file
findstr define %SDXROOT%\SymCrypt\inc\symcrypt_internal_shared.inc | findstr %1 >t.txt
set /p T=<t.txt

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
del t.txt
del tmp.txt