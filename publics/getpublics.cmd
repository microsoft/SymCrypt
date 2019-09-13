set SYMCRYPT_PUBLICS=%OBJECT_ROOT%\SymCrypt\Publics\%O%
set SYMCRYPT_PUBLICS_CACHE=\SymCryptPublicsCache
set SYMCRYPT_PUBLICS_MASTER=\\fsu\shares\symcrypt\ScPublics

echo obj entry: %O%,  %OBJ_PATH%

dir %SYMCRYPT_PUBLICS_CACHE%\inc
if NOT EXIST %SYMCRYPT_PUBLICS_CACHE%\inc\md2.h (
    xcopy %SYMCRYPT_PUBLICS_MASTER% %SYMCRYPT_PUBLICS_CACHE%\ /S /Y
    rem error Please check that the publics were copied to the local cache properly, and then re-run.
    rem exit /b 1
    )
xcopy %SYMCRYPT_PUBLICS_CACHE%\inc %SYMCRYPT_PUBLICS%\ /S /Y
copy %SYMCRYPT_PUBLICS_CACHE%\%build.arch%\*.lib %SYMCRYPT_PUBLICS%\ /Y


