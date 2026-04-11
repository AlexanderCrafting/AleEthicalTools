@echo off
REM Punto de entrada para Windows
REM Si Python no está en PATH, edita la ruta aquí

setlocal enabledelayedexpansion

echo.
echo   =================================================
echo       AleEthicalTools v1.0.0 - Suite de Auditoría Ética
echo              Seguridad para Auditoría Ética
echo   =================================================
echo.

REM Verificar si Python está instalado
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Error: Python no está instalado o no está en PATH
    echo [*] Descárgalo desde https://www.python.org
    pause
    exit /b 1
)

REM Obtener versión de Python
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [+] Python detectado: %PYTHON_VERSION%

REM Verificar archivos necesarios
if not exist "main.py" (
    echo [!] Error: main.py no encontrado
    pause
    exit /b 1
)
echo [+] Archivos necesarios verificados

REM Ejecutar setup.py if needed
if not exist "logs" (
    echo [*] Primera ejecución - preparando entorno...
    python setup.py
)

REM Ejecutar AleEthicalTools
echo.
echo [*] Iniciando AleEthicalTools...
echo.
python main.py

pause
