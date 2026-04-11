#!/bin/bash

# Punto de entrada para Linux/macOS
# AleEthicalTools v2.0.0

echo ""
echo "  ================================================="
echo "      AleEthicalTools v1.0.0 - Suite de Auditoría Ética"
echo "         Seguridad para Auditoría Ética"
echo "  ================================================="
echo ""

# Verificar si Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: Python3 no está instalado"
    echo "[*] Instálalo con: apt-get install python3 (Debian/Ubuntu)"
    echo "                  brew install python3 (macOS)"
    exit 1
fi

# Obtener versión de Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[+] Python detectado: $PYTHON_VERSION"

# Verificar archivos necesarios
if [ ! -f "main.py" ]; then
    echo "[!] Error: main.py no encontrado"
    exit 1
fi
echo "[+] Archivos necesarios verificados"

# Setup inicial
if [ ! -d "logs" ]; then
    echo "[*] Primera ejecución - preparando entorno..."
    python3 setup.py
fi

# Ejecutar AleScanner
echo ""
echo "[*] Iniciando AleScanner..."
echo ""
python3 main.py
