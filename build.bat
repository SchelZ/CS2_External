@echo off
setlocal enabledelayedexpansion

set MODE=%1
set SERVER=%2
if "%MODE%"=="" set MODE=debug

echo.
echo  [*] Mode: %MODE%
echo.

:: Random salt
for /f "delims=" %%S in ('powershell -NoProfile -Command "$b=New-Object byte[](16);(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b);[BitConverter]::ToString($b).Replace('-','')"') do set BUILD_SALT=%%S

:: Random fake export name
for /f "delims=" %%R in ('powershell -NoProfile -Command "-join((65..90)+(97..122)|Get-Random -Count 12|%%{[char]$_})"') do set FAKE_NAME=%%R

echo  [*] Build salt : %BUILD_SALT%
echo  [*] Fake name  : %FAKE_NAME%

if "%MODE%"=="release" (
  set SERVER_HOST=%SERVER%
  if "!SERVER_HOST!"=="" set SERVER_HOST=license.yourdomain.com
  echo  [*] Server: !SERVER_HOST!
  echo  [*] Compiling hardened release...

  nim c ^
    -f ^
    --app:gui ^
    -d:release ^
    -d:tlsStrict ^
    -d:danger ^
    -d:strip ^
    -d:ssl ^
    --opt:speed ^
    --mm:orc ^
    --threads:on ^
    --stackTrace:off ^
    --lineTrace:off ^
    --excessiveStackTrace:off ^
    --checks:off ^
    --assertions:off ^
    --panics:off ^
    --overflowChecks:off ^
    --boundChecks:off ^
    --floatChecks:off ^
    --styleCheck:off ^
    --hints:off ^
    --warnings:off ^
    -d:buildSalt=!BUILD_SALT! ^
    -d:serverHost=!SERVER_HOST! ^
    --passC:"-O3" ^
    --passC:"-masm=att" ^
    --passC:"-fomit-frame-pointer" ^
    --passC:"-fno-ident" ^
    --passC:"-fno-asynchronous-unwind-tables" ^
    --passC:"-fvisibility=hidden" ^
    --passC:"-ffunction-sections" ^
    --passC:"-fdata-sections" ^
    --passC:"-fno-stack-protector" ^
    --passC:"-fno-unwind-tables" ^
    --passC:"-march=x86-64-v2" ^
    --passC:"-msse4.2 -mavx2" ^
    --passL:"-Wl,--gc-sections" ^
    --passL:"-Wl,--strip-all" ^
    --passL:"-Wl,--no-seh" ^
    --passL:"-Wl,--exclude-all-symbols" ^
    --passL:"-Wl,--enable-runtime-pseudo-reloc" ^
    --passL:"-lgdi32 -luser32 -lkernel32 -lwinhttp -lbcrypt -liphlpapi -lole32 -lwinmm" ^
    -o:overlay_raw.exe ^
    src/main.nim

  if !ERRORLEVEL! neq 0 ( echo  [!] Compilation failed. & exit /b 1 )

  :: Strip any remaining debug info
  where strip >nul 2>&1 && strip --strip-all --strip-debug overlay_raw.exe

  :: Rename to final
  copy /b overlay_raw.exe overlay.exe >nul

  :: UPX pack
  where upx >nul 2>&1
  if !ERRORLEVEL! == 0 (
    echo  [*] UPX packing with LZMA...
    upx --best --lzma --overlay=strip overlay.exe
  ) else (
    echo  [~] UPX not found - get it at https://github.com/upx/upx/releases
  )

  del overlay_raw.exe >nul 2>&1

  echo.
  echo  [+] overlay.exe ready
  echo  Usage: overlay.exe game.exe LICENSE-XXXX-XXXX-XXXX

) else (
  echo  [*] Compiling debug build ^(console + traces^)...

  nim c ^
    -f ^
    --app:console ^
    -d:debug ^
    -d:ssl ^
    --threads:on ^
    --mm:orc ^
    --stackTrace:on ^
    --lineTrace:on ^
    --passC:"-masm=att" ^
    -d:buildSalt=DEVSALT00000000000000000000000000 ^
    --passL:"-Wl,--enable-runtime-pseudo-reloc" ^
    --passL:"-lgdi32 -luser32 -lkernel32 -lwinhttp -lbcrypt -liphlpapi -lole32 -lwinmm" ^
    -o:overlay_debug.exe ^
    src/main.nim

  if !ERRORLEVEL! neq 0 ( echo  [!] Compilation failed. & exit /b 1 )
  echo  [+] overlay_debug.exe ready
)

endlocal