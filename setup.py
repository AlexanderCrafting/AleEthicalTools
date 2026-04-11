#!/usr/bin/env python3
"""
Script de inicialización para AleEthicalTools
Prepara el entorno y valida dependencias
"""

import sys
import os
import subprocess
from pathlib import Path

def print_banner():
    print(r"""
   _____  .__           _________              
  /  _  \ |  |   ____  /   _____/ ____   ____  
 /  /_\  \|  | _/ __ \ \_____  \_/ __ \_/ ___\ 
/    |    \  |_\  ___/ /        \  ___/\  \___ 
\____|__  /____/\___  >_______  /\___  >\___  >
        \/          \/        \/     \/     \/ 
    """)
    print("AleEthicalTools v1.0.0 - Ethical Auditing Suite")
    print("=" * 60)

def check_python_version():
    """Verificar versión de Python"""
    if sys.version_info < (3, 7):
        print("[!] Error: Se requiere Python 3.7 o superior")
        print(f"[!] Tu versión: {sys.version}")
        sys.exit(1)
    print("[+] Python version OK:", sys.version.split()[0])

def create_directories():
    """Crear directorio necesarios"""
    dirs = [
        "logs",
        "reports", 
        "wordlists",
        "data",
        "cache"
    ]
    
    for dir_name in dirs:
        path = Path(dir_name)
        if not path.exists():
            path.mkdir(exist_ok=True)
            print(f"[+] Directorio creado: {dir_name}/")
        else:
            print(f"[+] Directorio existe: {dir_name}/")

def check_modules():
    """Verificar módulos opcionalesInstalados"""
    optional_modules = {
        "dns": "dnspython",
        "bs4": "beautifulsoup4",
    }
    
    print("\n[*] Verificando módulos opcionalesInstalados...")
    for module, package in optional_modules.items():
        try:
            __import__(module)
            print(f"[+] {package} está instalado")
        except ImportError:
            print(f"[!] {package} NO está instalado (opcional)")
            print(f"    Instalar con: pip install {package}")

def verify_files():
    """Verificar archivos necesarios"""
    required_files = [
        "main.py",
        "config.py",
        "utils.py",
        "network_tools.py",
    ]
    
    print("\n[*] Verificando archivos necesarios...")
    all_exist = True
    for file in required_files:
        if os.path.exists(file):
            print(f"[+] {file}")
        else:
            print(f"[!] FALTA: {file}")
            all_exist = False
    
    if not all_exist:
        print("[!] Faltan archivos críticos")
        return False
    return True

def run_tests():
    """Ejecutar pruebas básicas"""
    print("\n[*] Ejecutando pruebas...")
    try:
        # Test imports
        import config
        import utils
        import network_tools
        print("[+] Importaciones correctas")
        
        # Test directories
        from config import LOGS_DIR, REPORTS_DIR, WORDLISTS_DIR
        print("[+] Directorios accesibles")
        
        # Test logger
        logger = utils.ScanLogger()
        logger.log("INFO", "Test del logger")
        print("[+] Logger funcional")
        
        return True
    except Exception as e:
        print(f"[!] Error en pruebas: {e}")
        return False

def main():
    print_banner()
    
    try:
        print("\n[1/4] Verificando Python...")
        check_python_version()
        
        print("\n[2/4] Creando directorios...")
        create_directories()
        
        print("\n[3/4] Verificando módulos...")
        check_modules()
        
        print("\n[4/4] Validando instalación...")
        if not verify_files():
            print("\n[!] Instalación incompleta")
            sys.exit(1)
        
        if not run_tests():
            print("\n[!] Pruebas fallidas")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print("[+] Setup completado exitosamente!")
        print("[+] Ejecuta: python main.py")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[!] Error durante setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
