@echo off
setlocal

:: -----------------------------------------------------------------------
:: build.bat - builds systemdetection.dll (32-bit) using VS Build Tools
:: Run this from any directory, no need for Developer Command Prompt.
:: Output: systemdetection.dll in the same folder as this script.
:: -----------------------------------------------------------------------

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133
set WK=C:\Program Files (x86)\Windows Kits\10
set WK_VER=10.0.19041.0
set HERE=%~dp0

echo [1/2] Compiling wsock32.c ...

"%MSVC%\bin\Hostx64\x86\cl.exe" /c /MT /O2 ^
  "/I%MSVC%\include" ^
  "/I%WK%\Include\%WK_VER%\um" ^
  "/I%WK%\Include\%WK_VER%\shared" ^
  "/I%WK%\Include\%WK_VER%\ucrt" ^
  "/Fo:%HERE%wsock32.obj" ^
  "%HERE%wsock32.c"

if errorlevel 1 (
    echo FAILED: compile step
    exit /b 1
)

echo [2/2] Linking systemdetection.dll ...

"%MSVC%\bin\Hostx64\x86\link.exe" /DLL /MACHINE:X86 /NODEFAULTLIB ^
  "/DEF:%HERE%wsock32.def" ^
  "/OUT:%HERE%systemdetection.dll" ^
  "%HERE%wsock32.obj" ^
  "%MSVC%\lib\x86\libcmt.lib" ^
  "%MSVC%\lib\x86\libvcruntime.lib" ^
  "%MSVC%\lib\x86\oldnames.lib" ^
  "%WK%\Lib\%WK_VER%\ucrt\x86\libucrt.lib" ^
  "%WK%\Lib\%WK_VER%\um\x86\ws2_32.lib" ^
  "%WK%\Lib\%WK_VER%\um\x86\iphlpapi.lib" ^
  "%WK%\Lib\%WK_VER%\um\x86\kernel32.lib" ^
  "%WK%\Lib\%WK_VER%\um\x86\winmm.lib"

if errorlevel 1 (
    echo FAILED: link step
    pause
    exit /b 1
)

del "%HERE%wsock32.obj" >nul 2>&1
del "%HERE%systemdetection.lib" >nul 2>&1
del "%HERE%systemdetection.exp" >nul 2>&1

echo.
echo OK: systemdetection.dll built successfully.
echo     Copy systemdetection.dll next to conviction_game.exe.
pause
