@echo off
setlocal
set "CWM_ROOT=%~dp0.."
if not exist "%CWM_ROOT%\runtime\python.exe" (
  echo Complete packaged runtime missing; reinstall the distribution. 1>&2
  exit /b 2
)
"%CWM_ROOT%\runtime\python.exe" -I -B -m cwm %*
exit /b %errorlevel%
