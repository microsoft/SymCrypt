@echo off
setlocal enabledelayedexpansion

REM Batch script to build SymCrypt with both Rust and C implementations and run comparison tests
REM Usage: compare-rust-c-impls.bat [--rebuild] [additional args for symcryptunittest.exe]

REM Check for --rebuild flag
set REBUILD=0
set UNITTEST_ARGS=
if /I "%~1"=="--rebuild" (
    set REBUILD=1
    shift
)

REM Collect remaining arguments for unit test
:parse_args
if "%~1"=="" goto args_done
set UNITTEST_ARGS=!UNITTEST_ARGS! %1
shift
goto parse_args
:args_done

REM Detect host architecture
set ARCH=%PROCESSOR_ARCHITECTURE%
if /I not "%ARCH%"=="AMD64" if /I not "%ARCH%"=="ARM64" (
    echo Error: Unsupported architecture: %ARCH%
    exit /b 1
)

REM Set preset and directory names
set PRESET_NAME=Windows_%ARCH%_Release
set C_BUILD_DIR=build\cmake\%PRESET_NAME%
set RUST_BUILD_DIR=build\cmake\%PRESET_NAME%_SymCRust

REM Build paths for the executables
set UNITTEST_EXE=%RUST_BUILD_DIR%\exe\symcryptunittest.exe
set DYNAMIC_DLL=%C_BUILD_DIR%\exe\symcrypttestmodule.dll

REM Check if builds are needed
set NEED_BUILD=0
if %REBUILD%==1 (
    echo Rebuild requested...
    set NEED_BUILD=1
) else (
    if not exist "%UNITTEST_EXE%" (
        echo Unit test executable not found, building...
        set NEED_BUILD=1
    )
    if not exist "%DYNAMIC_DLL%" (
        echo Dynamic test module not found, building...
        set NEED_BUILD=1
    )
)

REM Build if necessary
if %NEED_BUILD%==1 (
    echo Building SymCrypt for %ARCH% architecture...
    echo.

    REM Build C implementation (without Rust)
    echo ========================================
    echo Building C implementation...
    echo ========================================
    cmake --preset %PRESET_NAME%
    if errorlevel 1 (
        echo Error: CMake configure failed for C implementation
        exit /b 1
    )

    cmake --build %C_BUILD_DIR%
    if errorlevel 1 (
        echo Error: Build failed for C implementation
        exit /b 1
    )
    echo.

    REM Build Rust implementation
    echo ========================================
    echo Building Rust implementation...
    echo ========================================
    cmake --preset %PRESET_NAME% -B %RUST_BUILD_DIR% -DSYMCRUST_CONFIG=MSRust
    if errorlevel 1 (
        echo Error: CMake configure failed for Rust implementation
        exit /b 1
    )

    cmake --build %RUST_BUILD_DIR%
    if errorlevel 1 (
        echo Error: Build failed for Rust implementation
        exit /b 1
    )
    echo.
) else (
    echo Using existing builds...
    echo.
)

REM Run unit tests with comparison
echo ========================================
echo Running unit tests...
echo ========================================
echo.
echo   SymCryptStatic  = Rust implementation
echo   SymCryptDynamic = C implementation
echo.
echo ========================================

REM Final check if files exist
if not exist "%UNITTEST_EXE%" (
    echo Error: Unit test executable not found at %UNITTEST_EXE%
    exit /b 1
)

if not exist "%DYNAMIC_DLL%" (
    echo Error: Dynamic test module not found at %DYNAMIC_DLL%
    exit /b 1
)

REM Run the tests with dynamic module and any additional arguments
"%UNITTEST_EXE%" dynamic:%DYNAMIC_DLL% %UNITTEST_ARGS%

exit /b %errorlevel%
