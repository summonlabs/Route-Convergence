@echo off
rem Route Convergence release validation.
rem
rem Usage: validate-release.cmd <source-dir> <work-dir>
rem
rem From a source tree (normally a fresh clone of the closure commit) this script:
rem   * configures and builds Release with /W4 /WX and zero tolerated warnings;
rem   * runs the complete test suite, examples included;
rem   * configures and builds Debug and runs the complete test suite again;
rem   * installs the package and builds and runs the independent downstream
rem     consumer against the installed artifacts only;
rem   * runs the benchmark.
rem
rem Every step is plain: there are no timeouts, retries or tolerated failures.

setlocal enabledelayedexpansion

rem A Visual Studio developer environment is required for the MSVC toolchain.  If
rem cl.exe is not already on PATH this prelude locates the newest Visual Studio
rem installation through vswhere and imports its x64 environment, so the script
rem works from a plain command prompt without baking in a machine specific path.
where cl.exe >nul 2>&1
if errorlevel 1 (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if not exist "!VSWHERE!" (
    echo FAILED: cl.exe is not on PATH and vswhere.exe was not found
    exit /b 1
  )
  for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
  if not defined VSINSTALL (
    echo FAILED: no Visual Studio installation with the C++ toolset was found
    exit /b 1
  )
  call "!VSINSTALL!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
  where cl.exe >nul 2>&1
  if errorlevel 1 (
    echo FAILED: importing the Visual Studio environment did not provide cl.exe
    exit /b 1
  )
)

set "SOURCE_DIR=%~f1"
set "WORK_DIR=%~f2"
if "%SOURCE_DIR%"=="" ( echo usage: validate-release.cmd ^<source-dir^> ^<work-dir^> & exit /b 2 )
if "%WORK_DIR%"=="" set "WORK_DIR=%SOURCE_DIR%\build-release-validation"
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"

echo == Release configure ==
cmake -S "%SOURCE_DIR%" -B "%WORK_DIR%\release" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 ( echo RELEASE CONFIGURE FAILED & exit /b 1 )

echo == Release build ==
cmake --build "%WORK_DIR%\release"
if errorlevel 1 ( echo RELEASE BUILD FAILED & exit /b 1 )

echo == Release test ==
ctest --test-dir "%WORK_DIR%\release" --output-on-failure
if errorlevel 1 ( echo RELEASE TESTS FAILED & exit /b 1 )

echo == Debug configure ==
cmake -S "%SOURCE_DIR%" -B "%WORK_DIR%\debug" -G Ninja -DCMAKE_BUILD_TYPE=Debug
if errorlevel 1 ( echo DEBUG CONFIGURE FAILED & exit /b 1 )

echo == Debug build ==
cmake --build "%WORK_DIR%\debug"
if errorlevel 1 ( echo DEBUG BUILD FAILED & exit /b 1 )

echo == Debug test ==
ctest --test-dir "%WORK_DIR%\debug" --output-on-failure
if errorlevel 1 ( echo DEBUG TESTS FAILED & exit /b 1 )

echo == Install and consumer ==
call "%SOURCE_DIR%\scripts\validate-install.cmd" "%SOURCE_DIR%" "%WORK_DIR%\release" "%WORK_DIR%\install"
if errorlevel 1 ( echo INSTALL VALIDATION FAILED & exit /b 1 )

echo == Benchmark ==
"%WORK_DIR%\release\bench\rc_benchmark.exe"
if errorlevel 1 ( echo BENCHMARK FAILED & exit /b 1 )

echo == CLI version ==
"%WORK_DIR%\release\rc_cli.exe" version
if errorlevel 1 ( echo CLI VERSION FAILED & exit /b 1 )

echo == CLI store inspect ==
"%WORK_DIR%\release\rc_cli.exe" store inspect --store "%WORK_DIR%\cli-inspect.store" 2>&1 | findstr /C:"RC_CLI_ERROR" >nul
if errorlevel 1 ( echo EXPECTED A STRUCTURED STORE ERROR & exit /b 1 )

echo release validation passed
endlocal
