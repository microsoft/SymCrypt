set SYMCRYPT_PUBLICS=%OBJECT_ROOT%\SymCrypt\Publics\%O%
set SYMCRYPT_PUBLICS_CACHE=\SymCryptPublicsCache

echo obj entry: %O%,  %OBJ_PATH%

if NOT EXIST %SYMCRYPT_PUBLICS_CACHE%\inc\md2.h (
    error Do not know how to populate publics cache
    exit /b 1
    )
xcopy %SYMCRYPT_PUBLICS_CACHE%\inc %SYMCRYPT_PUBLICS%\ /S /Y
copy %SYMCRYPT_PUBLICS_CACHE%\%build.arch%\*.lib %SYMCRYPT_PUBLICS%\ /Y


