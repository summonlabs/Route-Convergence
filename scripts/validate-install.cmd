@echo off
rem Route Convergence release validation: install the package and build and run
rem the independent downstream consumer against the installed artifacts only.
rem
rem Usage: validate-install.cmd <source-dir> <binary-dir> <install-prefix>
rem
rem The consumer project is a separate CMake project that must find the package
rem through find_package(RouteConvergence CONFIG REQUIRED); nothing from the
rem Route Convergence source tree is on its include path.

setlocal
rem Arguments are expanded to fully qualified paths, so relative arguments stay
rem usable even when the repository lives under a directory whose name has spaces.
set "SOURCE_DIR=%~f1"
set "BINARY_DIR=%~f2"
set "PREFIX=%~f3"

if "%SOURCE_DIR%"=="" ( echo usage: validate-install.cmd ^<source-dir^> ^<binary-dir^> ^<install-prefix^> & exit /b 2 )
if "%BINARY_DIR%"=="" ( echo usage: validate-install.cmd ^<source-dir^> ^<binary-dir^> ^<install-prefix^> & exit /b 2 )
if "%PREFIX%"=="" ( echo usage: validate-install.cmd ^<source-dir^> ^<binary-dir^> ^<install-prefix^> & exit /b 2 )

echo == install ==
cmake --install "%BINARY_DIR%" --prefix "%PREFIX%"
if errorlevel 1 exit /b 1

if not exist "%PREFIX%\lib\cmake\RouteConvergence\RouteConvergenceConfig.cmake" (
  echo FAILED: RouteConvergenceConfig.cmake was not installed
  exit /b 1
)
if not exist "%PREFIX%\lib\cmake\RouteConvergence\RouteConvergenceConfigVersion.cmake" (
  echo FAILED: RouteConvergenceConfigVersion.cmake was not installed
  exit /b 1
)
if not exist "%PREFIX%\lib\cmake\RouteConvergence\RouteConvergenceTargets.cmake" (
  echo FAILED: RouteConvergenceTargets.cmake was not installed
  exit /b 1
)
findstr /C:"SummonSoftwareLabs::RouteConvergence" "%PREFIX%\lib\cmake\RouteConvergence\RouteConvergenceTargets.cmake" >nul
if errorlevel 1 (
  echo FAILED: the exported target SummonSoftwareLabs::RouteConvergence is missing
  exit /b 1
)

echo == consumer configure ==
cmake -S "%SOURCE_DIR%\tests\consumer" -B "%BINARY_DIR%\consumer" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%PREFIX%"
if errorlevel 1 exit /b 1

echo == consumer build ==
cmake --build "%BINARY_DIR%\consumer"
if errorlevel 1 exit /b 1

echo == consumer run ==
"%BINARY_DIR%\consumer\rc_consumer.exe"
if errorlevel 1 exit /b 1

echo install validation passed
endlocal
