@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PYW=C:\Users\11739\AppData\Local\Programs\Python\Python310\pythonw.exe"
if exist "%PYW%" (
  start "" "%PYW%" "%~dp0MemOptimizer.pyw"
) else (
  start "" pythonw "%~dp0MemOptimizer.pyw"
)
