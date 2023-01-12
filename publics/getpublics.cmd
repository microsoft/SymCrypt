set SYMCRYPT_PUBLICS=%OBJECT_ROOT%\SymCrypt\Publics\%O%
set SYMCRYPT_PUBLICS_CACHE=..\unittest\SymCryptDependencies

echo obj entry: %O%,  %OBJ_PATH%

dir %SYMCRYPT_PUBLICS_CACHE%\inc
if NOT EXIST %SYMCRYPT_PUBLICS_CACHE%\inc\md2.h (
    rem error Please run git submodule init then git submodule update. This should populate SymCryptDependencies.
    exit /b 1
    )
xcopy %SYMCRYPT_PUBLICS_CACHE%\inc %SYMCRYPT_PUBLICS%\ /S /Y
copy %SYMCRYPT_PUBLICS_CACHE%\%build.arch%\*.lib %SYMCRYPT_PUBLICS%\ /Y


