#!/usr/bin/env python3
"""
AleEthicalTools v1.0.0
Multiherramienta profesional de seguridad para auditoría y pruebas éticas.

Autor: Alexander Crafting
Propósito: Auditoría de seguridad, investigación y educación
Uso: Ético y autorizado solamente
"""

import ipaddress
import os
import platform
import random
import re
import socket
import string
import subprocess
import sys
import threading
import queue
import urllib.parse
import urllib.request
import hashlib
from datetime import datetime

# Importar módulos locales
try:
    from config import (
        APP_NAME, VERSION, AUTHOR, LOGS_DIR, REPORTS_DIR, WORDLISTS_DIR,
        COMMON_SERVICES, USER_AGENTS, ETHICAL_DISCLAIMER, TIMEOUT_PING,
        TIMEOUT_PORT, TIMEOUT_HTTP, MAX_THREADS
    )
    from utils import ScanLogger, ReportGenerator, create_sample_wordlist
    from network_tools import (
        get_ip_info, check_port_service, extract_emails, extract_urls,
        extract_ips, extract_hashes, get_ssl_cert_info, analyze_http_response,
        dns_enumerate, banner_grab, scan_common_paths, whois_lookup
    )
    from security_tools import (
        check_password_strength, detect_phishing_indicators, analyze_wireless_security,
        check_port_security, analyze_url_safety, check_common_vulnerabilities,
        simulate_brute_force_difficulty, detect_default_credentials
    )
    from osint_tools import (
        search_user_github, search_user_reddit, search_user_twitter,
        search_user_instagram, search_email_compromised, gather_osint_profile,
        search_subdomain_enumeration, check_domain_availability,
        reverse_email_lookup, search_user_linkedin
    )
    from pentest_tools import (
        get_tool_info, list_all_tools, search_tools_by_category,
        get_installation_guide, get_commands_reference, get_learning_path,
        get_legal_guidelines, print_tool_details, PROFESSIONAL_TOOLS
    )
except ImportError as e:
    print(f"Error al importar módulos: {e}")
    sys.exit(1)

# Colores ANSI
ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_BLUE = "\033[94m"
ANSI_MAGENTA = "\033[95m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

# Logger global
logger = ScanLogger()

# Lock para threads
LOCK = threading.Lock()

def clear_screen():
    """Limpiar pantalla"""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def print_disclaimer():
    """Mostrar advertencia de uso ético"""
    print(ANSI_RED + ETHICAL_DISCLAIMER + ANSI_RESET)

def print_header():
    """Mostrar encabezado ASCII art"""
    clear_screen()
    print(ANSI_CYAN + ANSI_BOLD + r"""
   _____  .__           _________              
  /  _  \ |  |   ____  /   _____/ ____   ____  
 /  /_\  \|  | _/ __ \ \_____  \_/ __ \_/ ___\ 
/    |    \  |_\  ___/ /        \  ___/\  \___ 
\____|__  /____/\___  >_______  /\___  >\___  >
        \/          \/        \/     \/     \/ 
    """ + ANSI_RESET)
    
    version_line = f" v{VERSION} | {APP_NAME} | Por {AUTHOR}"
    print(ANSI_YELLOW + ANSI_BOLD + version_line.center(70) + ANSI_RESET)
    print(ANSI_GREEN + "═" * 70 + ANSI_RESET)
    print()

def safe_input(prompt_text):
    """Input seguro con manejo de interrupciones"""
    try:
        return input(prompt_text)
    except (EOFError, KeyboardInterrupt):
        print(ANSI_RED + "\n[!] Operación cancelada por el usuario." + ANSI_RESET)
        sys.exit(0)

def ping_host(host, timeout=TIMEOUT_PING):
    """Ping con captura de latencia"""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(host)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), str(host)]
    
    start_time = datetime.now()
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        latency = (datetime.now() - start_time).total_seconds() * 1000
        return result.returncode == 0, latency
    except FileNotFoundError:
        return False, None
    except Exception:
        return False, None

def scan_port(target, port, timeout=TIMEOUT_PORT):
    """Scan de puerto TCP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        return result == 0
    except OSError:
        return False
    finally:
        sock.close()

def parse_ipv4_range(ip_range_text):
    """Parsear rango de IPs en múltiples formatos"""
    try:
        if '/' in ip_range_text:
            network = ipaddress.ip_network(ip_range_text, strict=False)
            return list(network.hosts())
        elif '-' in ip_range_text:
            start, end = ip_range_text.split('-', 1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            return [ipaddress.ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
        else:
            return [ipaddress.ip_address(ip_range_text.strip())]
    except Exception:
        return []

def detect_local_network():
    """Detectar red local automáticamente"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if local_ip.startswith("127."):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
        network = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(network)
    except Exception:
        return None

def scan_ping_range(addresses):
    """Escaneo ICMP con reportes"""
    print(ANSI_CYAN + "\n[*] Escaneando hosts con ICMP..." + ANSI_RESET)
    print(ANSI_YELLOW + f"[*] Objetivo: {len(addresses)} hosts" + ANSI_RESET)
    
    start_time = datetime.now()
    reachable = []
    threads = []
    q = queue.Queue()

    def worker():
        while True:
            ip = q.get()
            if ip is None:
                break
            alive, latency = ping_host(str(ip))
            if alive:
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except:
                    hostname = "N/A"
                
                entry = {
                    "ip": str(ip),
                    "hostname": hostname,
                    "latency": latency,
                    "status": "Activo"
                }
                
                with LOCK:
                    reachable.append(entry)
                    latency_str = f"{latency:.0f}ms" if latency else "unknown"
                    print(ANSI_GREEN + f"[+] {str(ip):15} | {hostname:20} | {latency_str}" + ANSI_RESET)
            q.task_done()

    num_threads = min(max(100, len(addresses) // 10), MAX_THREADS)
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        threads.append(thread)

    for ip in addresses:
        q.put(ip)

    q.join()
    for _ in threads:
        q.put(None)
    for thread in threads:
        thread.join(timeout=0.5)

    elapsed = (datetime.now() - start_time).total_seconds()
    
    print(ANSI_CYAN + "\n" + "="*60 + ANSI_RESET)
    print(ANSI_YELLOW + f"[*] Escaneo completado en {elapsed:.2f}s" + ANSI_RESET)
    print(ANSI_GREEN + f"[+] {len(reachable)} host(s) activos de {len(addresses)}" + ANSI_RESET)
    print(ANSI_CYAN + "="*60 + ANSI_RESET)
    
    logger.log("INFO", f"Ping sweep completado: {len(reachable)}/{len(addresses)} hosts activos")
    
    return reachable

def scan_port_range(target, start_port, end_port):
    """Escaneo de puertos TCP con detalles"""
    print(ANSI_CYAN + f"\n[*] Escaneando puertos en {target}..." + ANSI_RESET)
    print(ANSI_YELLOW + f"[*] Rango: {start_port}-{end_port} ({end_port - start_port + 1} puertos)" + ANSI_RESET)
    
    start_time = datetime.now()
    open_ports = []
    q = queue.Queue()

    def worker():
        while True:
            port = q.get()
            if port is None:
                break
            if scan_port(target, port):
                service = COMMON_SERVICES.get(port, "unknown")
                with LOCK:
                    open_ports.append(port)
                    print(ANSI_GREEN + f"[+] {port:<6} open   {service}" + ANSI_RESET)
            q.task_done()

    num_threads = min(max(50, (end_port - start_port) // 20), MAX_THREADS)
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        threads.append(thread)

    for port in range(start_port, end_port + 1):
        q.put(port)

    q.join()
    for _ in threads:
        q.put(None)
    for thread in threads:
        thread.join(timeout=0.5)

    elapsed = (datetime.now() - start_time).total_seconds()
    
    print(ANSI_CYAN + "\n" + "="*60 + ANSI_RESET)
    print(ANSI_YELLOW + f"[*] Escaneo completado en {elapsed:.2f}s" + ANSI_RESET)
    print(ANSI_GREEN + f"[+] {len(open_ports)} puerto(s) abierto(s)" + ANSI_RESET)
    print(ANSI_YELLOW + f"[*] Tasa: {(end_port - start_port + 1) / elapsed:.0f} puertos/seg" + ANSI_RESET)
    print(ANSI_CYAN + "="*60 + ANSI_RESET)
    
    logger.log("INFO", f"Port scan completado: {len(open_ports)}/{end_port - start_port + 1} puertos abiertos")
    
    return open_ports

def menu_info_gathering():
    """Recopilación de información"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ INFORMATION GATHERING ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " DNS Lookup avanzado")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Información detallada de IP")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " WHOIS Lookup")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Headers HTTP y análisis")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Escanear rutas comunes")
        print(ANSI_CYAN + "[6]" + ANSI_RESET + " Certificado SSL/TLS")
        print(ANSI_CYAN + "[7]" + ANSI_RESET + " Enumerar subdominios")
        print(ANSI_CYAN + "[8]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            domain = safe_input(ANSI_YELLOW + "Dominio: " + ANSI_RESET).strip()
            if domain:
                print(ANSI_CYAN + "\n[*] Enumerando registros DNS..." + ANSI_RESET)
                records = dns_enumerate(domain)
                
                if records.get("error"):
                    print(ANSI_RED + f"[!] {records['error']}" + ANSI_RESET)
                else:
                    print(ANSI_GREEN + f"DNS Records para {domain}:" + ANSI_RESET)
                    for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
                        values = records.get(record_type, [])
                        if values:
                            print(ANSI_CYAN + f"\n{record_type} Records:" + ANSI_RESET)
                            for value in values:
                                print(f"  → {value}")
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "2":
            ip = safe_input(ANSI_YELLOW + "Dirección IP: " + ANSI_RESET).strip()
            if ip:
                print(ANSI_CYAN + "\n[*] Analizando IP..." + ANSI_RESET)
                info = get_ip_info(ip)
                print(ANSI_GREEN + "\nInformación de IP:" + ANSI_RESET)
                for key, value in info.items():
                    if value and key != "error":
                        print(f"  {key}: {value}")
                if info.get("error"):
                    print(ANSI_RED + f"  Error: {info['error']}" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "3":
            domain = safe_input(ANSI_YELLOW + "Dominio para WHOIS: " + ANSI_RESET).strip()
            if domain:
                print(ANSI_CYAN + "\n[*] Consulta WHOIS..." + ANSI_RESET)
                whois_result = whois_lookup(domain)
                
                if whois_result.get("error"):
                    print(ANSI_RED + f"[!] Error: {whois_result['error']}" + ANSI_RESET)
                elif whois_result.get("result"):
                    print(ANSI_GREEN + "WHOIS Response:" + ANSI_RESET)
                    # Mostrar solo las primeras 1500 caracteres
                    result_text = whois_result["result"][:1500]
                    print(ANSI_CYAN + result_text + ANSI_RESET)
                    if len(whois_result["result"]) > 1500:
                        print(ANSI_YELLOW + "\n[*] (Resultado truncado - primeros 1500 caracteres)" + ANSI_RESET)
                else:
                    print(ANSI_YELLOW + "[*] No WHOIS data available" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "4":
            url = safe_input(ANSI_YELLOW + "URL a analizar: " + ANSI_RESET).strip()
            if url:
                # Validar formato básico de URL
                if not url.startswith(("http://", "https://")):
                    url = "http://" + url
                
                print(ANSI_CYAN + "\n[*] Analizando respuesta HTTP..." + ANSI_RESET)
                analysis = analyze_http_response(url)
                
                if analysis.get("error"):
                    print(ANSI_RED + f"[!] Error: {analysis['error']}" + ANSI_RESET)
                    print(ANSI_YELLOW + "\n[*] Tips:" + ANSI_RESET)
                    print("    • Verifica que la URL sea correcta")
                    print("    • Comprueba tu conexión a Internet")
                    print("    • Si el error es DNS, el servidor puede no existir")
                elif analysis.get("status_code"):
                    print(ANSI_GREEN + f"Status Code: {analysis['status_code']}" + ANSI_RESET)
                    print(ANSI_GREEN + "\nHeaders principales:" + ANSI_RESET)
                    for header, value in list(analysis["headers"].items())[:8]:
                        print(f"  {header}: {value}")
                    if analysis["technologies"]:
                        print(ANSI_CYAN + "\nTecnologías detectadas:" + ANSI_RESET)
                        for tech in analysis["technologies"]:
                            print(f"  → {tech}")
                else:
                    print(ANSI_RED + "[!] No response from server" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "5":
            url = safe_input(ANSI_YELLOW + "URL base: " + ANSI_RESET).strip()
            if url:
                print(ANSI_CYAN + "\n[*] Escaneando rutas comunes..." + ANSI_RESET)
                paths = scan_common_paths(url)
                
                # Manejar el nuevo formato de resultado
                if isinstance(result, dict):
                    paths = result.get("accessible", [])
                    error = result.get("error")
                else:
                    # Legacy: si devuelve lista
                    paths = result
                    error = None
                
                if error:
                    print(ANSI_RED + f"[!] {error}" + ANSI_RESET)
                elif paths:
                    print(ANSI_GREEN + f"\n[+] {len(paths)} ruta(s) accesible(s):" + ANSI_RESET)
                    for path, status in paths:
                        status_color = ANSI_GREEN if status < 400 else ANSI_YELLOW
                        print(f"  {status_color}[{status}]{ANSI_RESET} {path}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron rutas accesibles." + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "6":
            hostname = safe_input(ANSI_YELLOW + "Hostname: " + ANSI_RESET).strip()
            if hostname:
                print(ANSI_CYAN + "\n[*] Obteniendo certificado SSL..." + ANSI_RESET)
                cert = get_ssl_cert_info(hostname)
                if not cert.get("error"):
                    print(ANSI_GREEN + "Información del certificado:" + ANSI_RESET)
                    for key, value in cert.items():
                        if value and key != "error":
                            print(f"  {key}: {value}")
                else:
                    print(ANSI_RED + f"Error: {cert.get('error')}" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "7":
            domain = safe_input(ANSI_YELLOW + "Dominio a enumerar: " + ANSI_RESET).strip()
            if domain:
                print(ANSI_CYAN + "\n[*] Enumerando subdominios..." + ANSI_RESET)
                result = search_subdomain_enumeration(domain)
                
                if result.get("found_subdomains"):
                    print(ANSI_GREEN + f"[+] {result.get('count')} subdominio(s) encontrado(s):" + ANSI_RESET)
                    for subdomain, ip in result.get("found_subdomains", []):
                        print(f"  {ANSI_GREEN}[+]{ANSI_RESET} {subdomain} → {ip}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron subdominios activos" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
        
        elif choice == "8":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_network_scanning():
    """Escaneo de red"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ NETWORK SCANNING ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Escaneo ping (rango)")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Escaneo de puertos")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Escaneo rápido red local")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Banner grabbing")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            text = safe_input(ANSI_YELLOW + "Rango (CIDR o IP-IP): " + ANSI_RESET).strip()
            addresses = parse_ipv4_range(text)
            if addresses:
                hosts = scan_ping_range(addresses)
                
                # Generar reporte
                report = ReportGenerator("ping_sweep", text)
                report.add_result("Hosts escaneados", len(addresses))
                report.add_result("Hosts activos", len(hosts))
                report_file = report.generate_html_report()
                print(ANSI_GREEN + f"\n[+] Reporte guardado: {report_file}" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
            else:
                print(ANSI_RED + "[!] Rango inválido" + ANSI_RESET)
                safe_input("Presiona Enter...")
        
        elif choice == "2":
            target = safe_input(ANSI_YELLOW + "IP o dominio: " + ANSI_RESET).strip()
            if target:
                ports_input = safe_input(ANSI_YELLOW + "Rango de puertos (default 1-1024): " + ANSI_RESET).strip()
                if not ports_input:
                    start_port, end_port = 1, 1024
                else:
                    try:
                        start_port, end_port = map(int, ports_input.split("-"))
                    except:
                        print(ANSI_RED + "[!] Formato inválido" + ANSI_RESET)
                        continue
                
                ports = scan_port_range(target, max(1, start_port), min(65535, end_port))
                
                # Generar reporte
                report = ReportGenerator("port_scan", target)
                report.add_result("Target", target)
                report.add_result("Puertos escaneados", end_port - start_port + 1)
                report.add_result("Puertos abiertos", len(ports))
                report_file = report.generate_html_report()
                print(ANSI_GREEN + f"\n[+] Reporte guardado: {report_file}" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
            else:
                print(ANSI_RED + "[!] Target inválido" + ANSI_RESET)
                safe_input("Presiona Enter...")
        
        elif choice == "3":
            network = detect_local_network()
            if network:
                print(ANSI_YELLOW + f"[*] Red detectada: {network}" + ANSI_RESET)
                addresses = parse_ipv4_range(network)
                hosts = scan_ping_range(addresses[:100])
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
            else:
                print(ANSI_RED + "[!] No se pudo detectar red local" + ANSI_RESET)
                safe_input("Presiona Enter...")
        
        elif choice == "4":
            host = safe_input(ANSI_YELLOW + "Hostname/IP: " + ANSI_RESET).strip()
            port_input = safe_input(ANSI_YELLOW + "Puerto: " + ANSI_RESET).strip()
            if host and port_input.isdigit():
                banner_data = banner_grab(host, int(port_input))
                
                if banner_data.get("error"):
                    print(ANSI_RED + f"\n[!] Error: {banner_data['error']}" + ANSI_RESET)
                elif banner_data.get("banner"):
                    print(ANSI_GREEN + f"\n[+] Banner ({host}:{port_input}):" + ANSI_RESET)
                    print(ANSI_CYAN + banner_data['banner'] + ANSI_RESET)
                else:
                    print(ANSI_YELLOW + "[*] No banner data available" + ANSI_RESET)
                
                safe_input(ANSI_CYAN + "\nPresiona Enter para continuar..." + ANSI_RESET)
            else:
                print(ANSI_RED + "[!] Parámetros inválidos" + ANSI_RESET)
                safe_input("Presiona Enter...")
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_web_tools():
    """Herramientas web"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ WEB TOOLS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Extraer emails de texto")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Extraer URLs")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Extraer IPs")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Extraer hashes")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            text = safe_input(ANSI_YELLOW + "Pega texto: " + ANSI_RESET).strip()
            if text:
                emails = extract_emails(text)
                if emails:
                    print(ANSI_GREEN + "\n[+] Emails encontrados:" + ANSI_RESET)
                    for email in set(emails):
                        print(f"  → {email}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron emails" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            text = safe_input(ANSI_YELLOW + "Pega texto: " + ANSI_RESET).strip()
            if text:
                urls = extract_urls(text)
                if urls:
                    print(ANSI_GREEN + "\n[+] URLs encontradas:" + ANSI_RESET)
                    for url in set(urls):
                        print(f"  → {url}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron URLs" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            text = safe_input(ANSI_YELLOW + "Pega texto: " + ANSI_RESET).strip()
            if text:
                ips = extract_ips(text)
                if ips:
                    print(ANSI_GREEN + "\n[+] IPs encontradas:" + ANSI_RESET)
                    for ip in set(ips):
                        print(f"  → {ip}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron IPs" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            text = safe_input(ANSI_YELLOW + "Pega texto: " + ANSI_RESET).strip()
            if text:
                hashes = extract_hashes(text)
                if hashes:
                    print(ANSI_GREEN + "\n[+] Hashes encontrados:" + ANSI_RESET)
                    for hash_type, values in hashes.items():
                        print(f"\n  {hash_type}:")
                        for h in values[:5]:
                            print(f"    → {h}")
                else:
                    print(ANSI_YELLOW + "[*] No se encontraron hashes" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_utils():
    """Utilidades misceláneas"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ UTILITIES ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Generador de contraseñas")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Hash generator (MD5/SHA1/SHA256)")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Información del sistema")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            length_input = safe_input(ANSI_YELLOW + "Longitud (default 16): " + ANSI_RESET).strip()
            length = int(length_input) if length_input.isdigit() else 16
            password = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=length))
            print(ANSI_GREEN + f"\n[+] Password: {password}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            text = safe_input(ANSI_YELLOW + "Texto a hashear: " + ANSI_RESET).strip()
            if text:
                print(ANSI_GREEN + "\n[+] Hashes" + ANSI_RESET)
                print(f"  MD5:    {hashlib.md5(text.encode()).hexdigest()}")
                print(f"  SHA1:   {hashlib.sha1(text.encode()).hexdigest()}")
                print(f"  SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_CYAN + "\n[*] Información del sistema:" + ANSI_RESET)
            print(f"  OS: {platform.system()} {platform.release()}")
            print(f"  Hostname: {socket.gethostname()}")
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
                print(f"  IP Local: {local_ip}")
            except:
                pass
            network = detect_local_network()
            print(f"  Red Local: {network or 'N/A'}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_professional_tools():
    """Menú de herramientas profesionales de pentesting"""
    from pentest_menu import display_menu_professional_tools
    display_menu_professional_tools(safe_input, print_header)

def menu_exploitation_tools():
    """Herramientas de explotación"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ EXPLOITATION TOOLS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Escaneo de puertos")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Escaneo ping")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Banner grabbing")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Enviar paquetes UDP")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            target = safe_input(ANSI_YELLOW + "IP o dominio: " + ANSI_RESET).strip()
            if target:
                ports_input = safe_input(ANSI_YELLOW + "Rango de puertos (default 1-1024): " + ANSI_RESET).strip()
                if not ports_input:
                    start_port, end_port = 1, 1024
                else:
                    try:
                        start_port, end_port = map(int, ports_input.split("-"))
                    except:
                        print(ANSI_RED + "[!] Formato inválido" + ANSI_RESET)
                        continue
                
                ports = scan_port_range(target, max(1, start_port), min(65535, end_port))
                report = ReportGenerator("port_scan", target)
                report.add_result("Target", target)
                report.add_result("Puertos escaneados", end_port - start_port + 1)
                report.add_result("Puertos abiertos", len(ports))
                report_file = report.generate_html_report()
                print(ANSI_GREEN + f"\n[+] Reporte guardado: {report_file}" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            text = safe_input(ANSI_YELLOW + "Rango (CIDR o IP-IP): " + ANSI_RESET).strip()
            addresses = parse_ipv4_range(text)
            if addresses:
                hosts = scan_ping_range(addresses)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
            else:
                print(ANSI_RED + "[!] Rango inválido" + ANSI_RESET)
                safe_input("Presiona Enter...")
        
        elif choice == "3":
            host = safe_input(ANSI_YELLOW + "Hostname/IP: " + ANSI_RESET).strip()
            port_input = safe_input(ANSI_YELLOW + "Puerto: " + ANSI_RESET).strip()
            if host and port_input.isdigit():
                banner_data = banner_grab(host, int(port_input))
                if banner_data.get("error"):
                    print(ANSI_RED + f"\n[!] Error: {banner_data['error']}" + ANSI_RESET)
                elif banner_data.get("banner"):
                    print(ANSI_GREEN + f"\n[+] Banner:" + ANSI_RESET)
                    print(ANSI_CYAN + banner_data['banner'] + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            network_text = safe_input(ANSI_YELLOW + "Rango de red (CIDR o IP-IP): " + ANSI_RESET).strip()
            addresses = parse_ipv4_range(network_text)
            if addresses:
                hosts = scan_ping_range(addresses)
                if hosts:
                    port = safe_input(ANSI_YELLOW + "Puerto UDP (default 53): " + ANSI_RESET).strip() or "53"
                    message = safe_input(ANSI_YELLOW + "Mensaje: " + ANSI_RESET).strip() or "AleEthicalTools Packet"
                    print(ANSI_YELLOW + f"[*] Enviando a {len(hosts)} hosts..." + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_sniffing_spoofing():
    """Sniffing y spoofing"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ SNIFFING & SPOOFING ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Ver interfaces de red")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Ver tabla ARP")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Información de red local")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_YELLOW + "\n[*] Interfaces de red:" + ANSI_RESET)
            if platform.system() == "Windows":
                os.system("ipconfig /all")
            else:
                os.system("ifconfig || ip addr")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_YELLOW + "\n[*] Tabla ARP:" + ANSI_RESET)
            os.system("arp -a" if platform.system() == "Windows" else "arp -a")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            network = detect_local_network()
            print(ANSI_CYAN + f"\n[*] Red local: {network}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_web_attack():
    """Web Attack Tools expandido"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ WEB ATTACK TOOLS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Buscar formularios")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Buscar enlaces")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Escanear rutas comunes")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            url = safe_input(ANSI_YELLOW + "URL: " + ANSI_RESET).strip()
            if url:
                print(ANSI_CYAN + "\n[*] Buscando formularios..." + ANSI_RESET)
                pattern = r'<form[^>]*>.*?</form>'
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")
                        forms = re.findall(pattern, html, re.S | re.I)
                        if forms:
                            print(ANSI_GREEN + f"[+] {len(forms)} formulario(s) encontrado(s)" + ANSI_RESET)
                except Exception as e:
                    print(ANSI_RED + f"[!] Error: {e}" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            url = safe_input(ANSI_YELLOW + "URL: " + ANSI_RESET).strip()
            if url:
                print(ANSI_CYAN + "\n[*] Buscando enlaces..." + ANSI_RESET)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")
                        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
                        if links:
                            print(ANSI_GREEN + f"[+] {len(links)} enlace(s) encontrado(s)" + ANSI_RESET)
                            for link in links[:10]:
                                print(f"  → {link}")
                except Exception as e:
                    print(ANSI_RED + f"[!] Error: {e}" + ANSI_RESET)
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            url = safe_input(ANSI_YELLOW + "URL base: " + ANSI_RESET).strip()
            if url:
                result = scan_common_paths(url)
                if isinstance(result, dict):
                    paths = result.get("accessible", [])
                    error = result.get("error")
                else:
                    paths = result
                    error = None
                
                if error:
                    print(ANSI_RED + f"[!] {error}" + ANSI_RESET)
                elif paths:
                    print(ANSI_GREEN + f"[+] {len(paths)} ruta(s) accesible(s)" + ANSI_RESET)
                    for path, status in paths[:10]:
                        print(f"  [{status}] {path}")
                safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_cam_hacking():
    """Seguridad de cámaras IP - Detección y Hardening"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ SEGURIDAD DE CÁMARAS IP ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Puertos comunes de cámaras")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Credenciales por defecto")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Vulnerabilidades comunes")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Hardening de cámaras")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_GREEN + "\n[+] PUERTOS COMUNES DE CÁMARAS IP" + ANSI_RESET)
            ports = [
                (554, "RTSP (Real Time Streaming Protocol)"),
                (80, "HTTP (interfaz web)"),
                (443, "HTTPS (interfaz web seguro)"),
                (8000, "HTTP alternativo"),
                (8080, "HTTP alternativo"),
                (8081, "HTTP alternativo"),
                (9000, "Algunos modelos específicos"),
            ]
            for port, description in ports:
                print(f"   • Puerto {port}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_RED + "\n[!] CREDENCIALES POR DEFECTO" + ANSI_RESET)
            print("   Usuario: admin")
            print("   Passwords comunes:")
            print("      • 12345")
            print("      • admin")
            print("      • (vacío)")
            print("      • 888888")
            print("      • 123456")
            print("\n   ⚠️ CAMBIAR SIEMPRE LAS CREDENCIALES POR DEFECTO")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_RED + "\n[!] VULNERABILIDADES COMUNES" + ANSI_RESET)
            vulns = [
                "Credentials por defecto sin cambiar",
                "Interfaces web sin HTTPS",
                "Falta de autenticación fuerte",
                "Firmware desactualizado",
                "Buffer overflows en aplicaciones",
                "Credential stuffing (usuarios reuses)",
                "Transmisión de video sin encripción",
            ]
            for vuln in vulns:
                print(f"   • {vuln}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_GREEN + "\n[+] RECOMENDACIONES DE SEGURIDAD" + ANSI_RESET)
            recommendations = [
                "1. Cambiar credenciales por defecto inmediatamente",
                "2. Usar contraseñas fuertes (min 12 caracteres)",
                "3. Actualizar firmware regularmente",
                "4. Acceder solo via HTTPS en redes públicas",
                "5. Utilizar VPN para acceso remoto",
                "6. Segmentar cámaras en red separada (VLAN)",
                "7. Desactivar servicios innecesarios",
                "8. Monitorear acceso y registros (logs)",
                "9. Usar puertos no estándar si es posible",
                "10. Configurar firewall restrictivo",
            ]
            for rec in recommendations:
                print(f"   {rec}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_remote_trojan():
    """Remote Trojan RAT"""
    print_header()
    print(ANSI_CYAN + "━━━━━ REMOTE TROJAN RAT ━━━━━" + ANSI_RESET)
    print(ANSI_YELLOW + "[*] Esta herramienta NO genera RATs maliciosos" + ANSI_RESET)
    print(ANSI_YELLOW + "[*] Este módulo es solo informativo sobre seguridad" + ANSI_RESET)
    print("\n[*] Medidas de defensa:")
    print("    • Mantén actualizados los sistemas")
    print("    • Usa software antivirus/EDR")
    print("    • Revisa conexiones activas (netstat)")
    print("    • Monitorea procesos sospechosos")
    safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)

def menu_sql_injection():
    """SQL Injection - Detection & Prevention"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ SQL INJECTION DETECTION & DEFENSE ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Mostrar payloads comunes (educativo)")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Metodología de protección")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Indicadores de vulnerabilidad SQL")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_RED + "\n[!] PAYLOADS COMUNES DE SQL INJECTION (EDUCACIONAL)" + ANSI_RESET)
            payloads = [
                ("OR 1=1", "' OR '1'='1"),
                ("OR 1=1--", "1' OR '1'='1'--"),
                ("UNION SELECT", "1' UNION SELECT NULL, NULL--"),
                ("Comment", "admin'--"),
                ("Time-based blind", "1' AND SLEEP(5)--"),
            ]
            for name, payload in payloads:
                print(f"   {name}:")
                print(f"      {payload}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_GREEN + "\n[+] METODOLOGÍA DE PROTECCIÓN" + ANSI_RESET)
            methods = [
                ("Prepared Statements", "Usa placeholders (?), no concatenación"),
                ("Input Validation", "Valida tipo, longitud, formato"),
                ("Whitelisting", "Solo permite valores conocidos buenos"),
                ("Escape Characters", "Escapa caracteres especiales"),
                ("Least Privilege", "DB user con permisos mínimos"),
                ("Error Handling", "No muestres errores detallados"),
                ("WAF", "Usa Web Application Firewall"),
                ("Security Scans", "Auditorías regulares de código"),
            ]
            for method, description in methods:
                print(f"   • {method}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_RED + "\n[!] INDICADORES DE VULNERABILIDAD SQL" + ANSI_RESET)
            indicators = [
                "• Errores SQL mostrados en páginas",
                "• Input que modifica consultas de forma inesperada",
                "• Retrasos en respuestas con ciertos inputs",
                "• Union-based queries que revelan estructura",
                "• Booleanos que cambian con inputs específicos",
                "• Falta de validación de entrada",
                "• Concatenación de strings en queries",
            ]
            for indicator in indicators:
                print(f"   {indicator}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_social_media_brute():
    """Social Media Username Availability - Busca disponibilidad de usernames"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ SOCIAL MEDIA USERNAME CHECKER ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Buscar disponibilidad de username")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Generar variaciones y buscar")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            username = safe_input(ANSI_YELLOW + "\nUsername a buscar: " + ANSI_RESET).strip()
            if username:
                print(ANSI_CYAN + "\n[*] Verificando disponibilidad..." + ANSI_RESET)
                platforms = [
                    ("github", f"https://github.com/{username}"),
                    ("twitter", f"https://twitter.com/{username}"),
                    ("reddit", f"https://reddit.com/user/{username}"),
                    ("instagram", f"https://instagram.com/{username}"),
                    ("twitch", f"https://twitch.tv/{username}"),
                    ("youtube", f"https://youtube.com/@{username}"),
                    ("tiktok", f"https://tiktok.com/@{username}"),
                ]
                
                available = []
                taken = []
                
                for platform, url in platforms:
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                        resp = urllib.request.urlopen(req, timeout=3)
                        taken.append(platform)
                        print(f"    {ANSI_RED}[✗]{ANSI_RESET} {platform}: Tomado")
                    except:
                        available.append(platform)
                        print(f"    {ANSI_GREEN}[✓]{ANSI_RESET} {platform}: Disponible")
                
                print(ANSI_GREEN + f"\n[+] Disponibles: {', '.join(available) if available else 'Ninguno'}" + ANSI_RESET)
                print(ANSI_RED + f"[!] Tomados: {', '.join(taken) if taken else 'Ninguno'}" + ANSI_RESET)
            
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            username = safe_input(ANSI_YELLOW + "\nUsername base: " + ANSI_RESET).strip()
            if username:
                print(ANSI_CYAN + "\n[*] Generando variaciones..." + ANSI_RESET)
                variations = [
                    username,
                    f"{username}123",
                    f"{username}2024",
                    f"{username}_",
                    f"{username}.",
                    f"_{username}",
                    f"{username}pro",
                    f"{username}real",
                    f"{username}official",
                ]
                
                print(ANSI_GREEN + f"\n[+] Variaciones a probar:" + ANSI_RESET)
                for var in variations:
                    print(f"    → {var}")
                
                print(ANSI_CYAN + "\n[*] Probando variaciones en GitHub..." + ANSI_RESET)
                for var in variations:
                    result = search_user_github(var)
                    if result.get("found"):
                        print(ANSI_GREEN + f"    [+] {var} (GitHub): {result.get('url')}" + ANSI_RESET)
                    else:
                        print(f"    [✗] {var}: No encontrado")
            
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_social_media_finder():
    """Social Media OSINT - Búsqueda real de usuarios"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ SOCIAL MEDIA FINDER - OSINT ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Buscar usuario (GitHub, Reddit, etc)")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Verificar si email fue hackeado")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Búsqueda inversa de email")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Perfil OSINT completo")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            username = safe_input(ANSI_YELLOW + "\nUsuario a buscar: " + ANSI_RESET).strip()
            if username:
                print(ANSI_CYAN + "\n[*] Buscando en múltiples plataformas..." + ANSI_RESET)
                
                # GitHub
                print(f"{ANSI_CYAN}[*] GitHub...{ANSI_RESET}")
                github_result = search_user_github(username)
                if github_result.get("found"):
                    print(ANSI_GREEN + f"[+] GitHub encontrado:" + ANSI_RESET)
                    print(f"    Nombre: {github_result.get('name')}")
                    print(f"    Bio: {github_result.get('bio')}")
                    print(f"    Repos: {github_result.get('repos')}")
                    print(f"    Followers: {github_result.get('followers')}")
                    print(f"    URL: {github_result.get('url')}")
                else:
                    print(f"{ANSI_RED}[!] No encontrado en GitHub{ANSI_RESET}")
                
                # Reddit
                print(f"\n{ANSI_CYAN}[*] Reddit...{ANSI_RESET}")
                reddit_result = search_user_reddit(username)
                if reddit_result.get("found"):
                    print(ANSI_GREEN + f"[+] Reddit encontrado:" + ANSI_RESET)
                    print(f"    Karma: {reddit_result.get('karma')}")
                    print(f"    URL: {reddit_result.get('url')}")
                else:
                    print(f"{ANSI_RED}[!] No encontrado en Reddit{ANSI_RESET}")
                
                # Twitter
                print(f"\n{ANSI_CYAN}[*] Twitter/X...{ANSI_RESET}")
                twitter_result = search_user_twitter(username)
                if twitter_result.get("found"):
                    print(ANSI_GREEN + f"[+] Twitter encontrado: {twitter_result.get('url')}" + ANSI_RESET)
                else:
                    print(f"{ANSI_RED}[!] No encontrado en Twitter{ANSI_RESET}")
                
                # Instagram
                print(f"\n{ANSI_CYAN}[*] Instagram...{ANSI_RESET}")
                insta_result = search_user_instagram(username)
                if insta_result.get("found"):
                    print(ANSI_GREEN + f"[+] Instagram encontrado: {insta_result.get('url')}" + ANSI_RESET)
                else:
                    print(f"{ANSI_RED}[!] No encontrado en Instagram{ANSI_RESET}")
                
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            email = safe_input(ANSI_YELLOW + "\nEmail a verificar: " + ANSI_RESET).strip()
            if email:
                print(ANSI_CYAN + "\n[*] Verificando en Have I Been Pwned..." + ANSI_RESET)
                result = search_email_compromised(email)
                
                if result.get("compromised"):
                    print(ANSI_RED + f"[!] Email COMPROMETIDO en {result.get('count')} brechas:" + ANSI_RESET)
                    for breach in result.get("breaches", []):
                        print(f"    • {breach}")
                elif result.get("compromised") == False:
                    print(ANSI_GREEN + "[+] Email NO encontrado en brechas conocidas" + ANSI_RESET)
                else:
                    print(ANSI_YELLOW + f"[*] {result.get('error')}" + ANSI_RESET)
            
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            email = safe_input(ANSI_YELLOW + "\nEmail a buscar: " + ANSI_RESET).strip()
            if email:
                print(ANSI_CYAN + "\n[*] Buscando email en servicios públicos..." + ANSI_RESET)
                result = reverse_email_lookup(email)
                
                if result.get("found_on"):
                    print(ANSI_GREEN + f"[+] Email encontrado en:" + ANSI_RESET)
                    for service in result.get("found_on"):
                        print(f"    • {service}")
                else:
                    print(ANSI_YELLOW + "[*] Email no indexado en servicios públicos búsquedos" + ANSI_RESET)
            
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            username = safe_input(ANSI_YELLOW + "\nUsername para perfil completo: " + ANSI_RESET).strip()
            if username:
                profile = gather_osint_profile(username)
                
                print(ANSI_GREEN + f"\n[+] PERFIL OSINT PARA: {username}" + ANSI_RESET)
                
                for source, data in profile.get("sources", {}).items():
                    print(f"\n{ANSI_CYAN}[*] {source.upper()}:{ANSI_RESET}")
                    if isinstance(data, dict):
                        if data.get("found") or data.get("error"):
                            if data.get("found"):
                                for key, value in data.items():
                                    if key != "found":
                                        print(f"    {key}: {value}")
                            else:
                                print(f"    [!] {data.get('error', 'No encontrado')}")
                        else:
                            for key, value in data.items():
                                print(f"    {key}: {value}")
            
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_ddos_tools():
    """DDOS Detection & Defense - Herramientas defensivas"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ DDOS DETECTION & DEFENSE ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Simulación de patrones de ataque DDoS")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Estrategias de mitigación")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Análisis de tráfico anómalo")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_YELLOW + "\n[*] Patrones comunes de ataque DDoS (educativo):" + ANSI_RESET)
            patterns = {
                "Volumétric": "Inunda con tráfico masivo (UDP flood, DNS amplification)",
                "Protocol-based": "Explota debilidades de protocolo (SYN flood, Ping of Death)",
                "Application-layer": "Ataca aplicación específica (HTTP flood)",
                "Slowloris": "Conexiones lentas para agotar recursos",
            }
            for attack_type, description in patterns.items():
                print(f"   • {attack_type}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_GREEN + "\n[+] ESTRATEGIAS DE MITIGACIÓN" + ANSI_RESET)
            strategies = [
                "1. Rate Limiting - Limita peticiones por IP/segundo",
                "2. CDN - Distribuye carga en múltiples servidores",
                "3. WAF (Web Application Firewall) - Filtra tráfico malicioso",
                "4. Blackhole Routing - Rechaza tráfico sospechoso",
                "5. IP Reputation - Bloquea IPs conocidas como maliciosas",
                "6. Behavioral Analysis - Detecta patrones anómalos",
                "7. Backup conexión - Conexión secundaria para redundancia",
                "8. Plan de respuesta - Protocolo establecido para incidentes",
            ]
            for strategy in strategies:
                print(f"   {strategy}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_YELLOW + "\n[*] Indicadores de tráfico anómalo:" + ANSI_RESET)
            indicators = [
                "• Aumento súbito de peticiones de una IP",
                "• IPs de múltiples países simultáneamente",
                "• Patrones de User-Agent idénticos",
                "• Requests a endpoints inexistentes",
                "• Respuestas lentificadas sin carga normal",
                "• Ciertos tipos de peticiones concentrados",
                "• Conexiones de corta duración repetidas",
            ]
            for indicator in indicators:
                print(f"   {indicator}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_phishing_tools():
    """Phishing Attack Tools - Detección y Prevención"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ PHISHING DETECTION & AWARENESS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Analizar email para phishing")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Analizar seguridad de URL")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Guía de prevención de phishing")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_YELLOW + "\nPega contenido de email para analizar:" + ANSI_RESET)
            email_text = safe_input(ANSI_YELLOW + "Email: " + ANSI_RESET).strip()
            if email_text:
                indicators = detect_phishing_indicators(email_text)
                print(ANSI_GREEN + f"\n[+] Análisis completado (Score: {indicators['score']})" + ANSI_RESET)
                if indicators["high_risk"]:
                    print(ANSI_RED + f"\n[!] Indicadores de ALTO riesgo:" + ANSI_RESET)
                    for ind in indicators["high_risk"]:
                        print(f"    ✗ {ind}")
                if indicators["medium_risk"]:
                    print(ANSI_YELLOW + f"\n[*] Indicadores de riesgo MEDIO:" + ANSI_RESET)
                    for ind in indicators["medium_risk"]:
                        print(f"    ⚠ {ind}")
                if indicators["suspicious_links"]:
                    print(ANSI_YELLOW + f"\n[*] URLs sospechosas encontradas:" + ANSI_RESET)
                    for url in indicators["suspicious_links"]:
                        print(f"    → {url}")
                risk_color = ANSI_RED if indicators["score"] > 3 else ANSI_YELLOW if indicators["score"] > 1 else ANSI_GREEN
                print(f"\n{risk_color}[*] Riesgo: {'ALTO' if indicators['score'] > 3 else 'MEDIO' if indicators['score'] > 1 else 'BAJO'}{ANSI_RESET}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            url = safe_input(ANSI_YELLOW + "\nURL a analizar: " + ANSI_RESET).strip()
            if url:
                analysis = analyze_url_safety(url)
                print(ANSI_GREEN + f"\n[+] Análisis de URL completado" + ANSI_RESET)
                if analysis["warnings"]:
                    print(ANSI_YELLOW + "[!] Advertencias encontradas:" + ANSI_RESET)
                    for warning in analysis["warnings"]:
                        print(f"    ⚠ {warning}")
                else:
                    print(ANSI_GREEN + "[+] URL aparenta ser segura" + ANSI_RESET)
                safety_color = ANSI_GREEN if analysis["safe"] else ANSI_RED
                print(f"\n{safety_color}[*] Estado: {'SEGURA' if analysis['safe'] else 'SOSPECHOSA'}{ANSI_RESET}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_GREEN + "\n[+] GUÍA DE PREVENCIÓN DE PHISHING" + ANSI_RESET)
            tips = [
                "1. Verifica siempre la dirección del remitente",
                "2. No hagas clic en enlaces desconocidos",
                "3. Usa HTTPS (candado verde) en sitios sensibles",
                "4. Cuestiona solicitudes urgentes de credenciales",
                "5. Busca errores de ortografía o formateo extraño",
                "6. Detecta URLs que imitan dominios legítimos",
                "7. No descargues archivos de fuentes desconocidas",
                "8. Pasa el mouse sobre enlaces para ver URL real",
                "9. Reporta emails sospechosos a tu empresa",
                "10. Usa autenticación de dos factores (2FA)",
            ]
            for tip in tips:
                print(f"   {tip}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_hash_cracking():
    """Hash Cracking Tools - Password Strength & Recovery"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ HASH & PASSWORD SECURITY ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Verificar fortaleza de contraseña")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Intentar crack de hash")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Calcular dificultad de fuerza bruta")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Detectar credenciales default")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            password = safe_input(ANSI_YELLOW + "\nContraseña a verificar: " + ANSI_RESET).strip()
            if password:
                strength = check_password_strength(password)
                color = ANSI_GREEN if strength["rating"] in ["Fuerte", "Muy fuerte"] else ANSI_YELLOW if strength["rating"] == "Moderada" else ANSI_RED
                print(f"\n{color}[*] Fortaleza: {strength['rating']}{ANSI_RESET}")
                print(f"   Puntuación: {strength['score']}/7")
                if strength["feedback"]:
                    print(ANSI_YELLOW + "\n[*] Sugerencias:" + ANSI_RESET)
                    for feedback in strength["feedback"]:
                        print(f"   → {feedback}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            hash_input = safe_input(ANSI_YELLOW + "\nHash (MD5/SHA1/SHA256): " + ANSI_RESET).strip()
            if hash_input:
                wordlist_file = safe_input(ANSI_YELLOW + "Wordlist (opcional): " + ANSI_RESET).strip() or "wordlists/common_passwords.txt"
                words = ["password", "123456", "admin", "root", "test"]
                
                if wordlist_file and os.path.exists(wordlist_file):
                    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                        words = [w.strip() for w in f if w.strip()]
                
                print(ANSI_CYAN + "\n[*] Intentando crack..." + ANSI_RESET)
                found = False
                for word in words[:100]:
                    for algo in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
                        if algo(word.encode()).hexdigest() == hash_input.lower():
                            print(ANSI_GREEN + f"[+] ¡Encontrado! {word} ({algo.__name__})" + ANSI_RESET)
                            found = True
                            break
                    if found:
                        break
                
                if not found:
                    print(ANSI_YELLOW + "[*] No se encontró en wordlist (intenta con otra)" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_YELLOW + "\n[*] Calcular dificultad de ataque por fuerza bruta" + ANSI_RESET)
            char_set = safe_input(ANSI_YELLOW + "Tamaño conjunto (ej: 94 para caracteres ASCII): " + ANSI_RESET).strip()
            length = safe_input(ANSI_YELLOW + "Longitud contraseña: " + ANSI_RESET).strip()
            
            if char_set.isdigit() and length.isdigit():
                difficulty = simulate_brute_force_difficulty(int(char_set), int(length))
                print(ANSI_GREEN + f"\n[+] Análisis completado" + ANSI_RESET)
                print(f"   Total combinaciones: {difficulty['total_combinations']:,.0f}")
                print(f"   Tiempo promedio: {difficulty['days']:.1f} días")
                if difficulty['years'] > 0:
                    print(f"   En años: {difficulty['years']:.2e}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            defaults = detect_default_credentials()
            print(ANSI_RED + "\n[!] CREDENCIALES DEFAULT COMUNES (¡Cambiar inmediatamente!)" + ANSI_RESET)
            for device, creds in defaults.items():
                print(f"\n   {device}:")
                print(f"     Usuario: {creds['user']}")
                print(f"     Contraseña: {creds['pass'] or '(vacía/ninguna)'}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_wordlist_gen():
    """Wordlist Generator - Para pentesting educativo"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ WORDLIST GENERATOR ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Wordlist simple (número secuencial)")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Wordlist con variaciones")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Wordlist de usuarios comunes")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Wordlist de password patterns")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            base = safe_input(ANSI_YELLOW + "Palabra base: " + ANSI_RESET).strip() or "palabra"
            count_str = safe_input(ANSI_YELLOW + "Cantidad (max 100): " + ANSI_RESET).strip() or "20"
            try:
                count = min(int(count_str), 100)
            except:
                count = 20
            
            print(ANSI_GREEN + "\n[+] Wordlist generado:" + ANSI_RESET)
            for i in range(1, count + 1):
                print(f"  {base}{i}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            base = safe_input(ANSI_YELLOW + "Palabra base: " + ANSI_RESET).strip() or "admin"
            print(ANSI_GREEN + "\n[+] Variaciones generadas:" + ANSI_RESET)
            variations = [
                base,
                base + "123",
                base + "1",
                base + "2024",
                base + "!",
                base + "@",
                base.upper(),
                base.capitalize(),
                "0" + base,
                base + "pass",
            ]
            for var in variations:
                print(f"  {var}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_GREEN + "\n[+] Usuarios comunes en sistemas:" + ANSI_RESET)
            users = [
                "admin", "administrator", "root", "user", "test", "guest",
                "support", "webmaster", "master", "manager", "operator",
                "system", "postgres", "mysql", "oracle", "backup"
            ]
            for user in users:
                print(f"  {user}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_GREEN + "\n[+] Patrones de password comunes:" + ANSI_RESET)
            patterns = [
                "password", "123456", "12345678", "qwerty", "abc123",
                "123123", "111111", "1234567", "password123", "12345",
                "letmein", "welcome", "monkey", "dragon", "master"
            ]
            for pattern in patterns:
                print(f"  {pattern}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")
            break
    
    safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)

def menu_xss_tools():
    """XSS - Detection & Prevention"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ XSS (CROSS-SITE SCRIPTING) DETECTION ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Mostrar tipos de XSS")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Payloads comunes (educativo)")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Prevención y mitigación")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Indicadores de vulnerabilidad")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_GREEN + "\n[+] TIPOS DE XSS" + ANSI_RESET)
            types = [
                ("Stored XSS", "Malicious script almacenado en servidor/BD"),
                ("Reflected XSS", "Script reflejado en respuesta sin guardar"),
                ("DOM-based XSS", "Vulnerabilidad en código JavaScript del cliente"),
                ("Blind XSS", "Payload ejecutado pero sin confirmación visual"),
            ]
            for name, description in types:
                print(f"   • {name}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_RED + "\n[!] PAYLOADS COMUNES DE XSS (EDUCACIONAL)" + ANSI_RESET)
            payloads = [
                ("<script>", "<script>alert('XSS')</script>"),
                ("Event handlers", "<img src=x onerror=alert('XSS')>"),
                ("SVG", "<svg onload=alert('XSS')>"),
                ("Body load", "<body onload=alert('XSS')>"),
                ("HTML5", "<input onfocus=alert('XSS') autofocus>"),
                ("Data URI", "<iframe src=data:text/html,<script>alert('XSS')</script>>"),
            ]
            for name, payload in payloads:
                print(f"   {name}:")
                print(f"      {payload}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_GREEN + "\n[+] PREVENCIÓN DE XSS" + ANSI_RESET)
            prevention = [
                ("Input Validation", "Valida y sanitiza entrada del usuario"),
                ("Output Encoding", "Encoda caracteres especiales en output"),
                ("Content Security Policy", "CSP headers para limitar ejecución de scripts"),
                ("HttpOnly Cookies", "Evita acceso a cookies desde JavaScript"),
                ("CORS Configuration", "Limita origen de solicitudes cross-origin"),
                ("Frameworks seguros", "Usa frameworks con protección automática"),
                ("Web Application Firewall", "Detecta y bloquea payloads XSS"),
            ]
            for method, description in prevention:
                print(f"   • {method}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_RED + "\n[!] INDICADORES DE VULNERABILIDAD XSS" + ANSI_RESET)
            indicators = [
                "• Input fields que aceptan cualquier carácter",
                "• Output sin validación en páginas",
                "• URLs con parámetros que aparecen en HTML",
                "• Comentarios de usuarios mostrados sin sanitizar",
                "• Falta de CSP headers",
                "• JavaScript que maneja entrada de usuario",
                "• eval() o similar ejecutando strings del usuario",
            ]
            for indicator in indicators:
                print(f"   {indicator}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_discord_leaks():
    """Discord Leaks"""
    print_header()
    print(ANSI_CYAN + "━━━━━ DISCORD LEAKS ━━━━━" + ANSI_RESET)
    text = safe_input(ANSI_YELLOW + "Pega texto para buscar tokens: " + ANSI_RESET).strip()
    if text:
        pattern = r"[A-Za-z0-9_\.-]{24}\.[A-Za-z0-9_\.-]{6}\.[A-Za-z0-9_\.-]{27}"
        tokens = re.findall(pattern, text)
        if tokens:
            print(ANSI_GREEN + f"[+] {len(tokens)} token(s) encontrado(s)" + ANSI_RESET)
        else:
            print(ANSI_YELLOW + "[*] No se encontraron tokens" + ANSI_RESET)
    safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)

def menu_telegram_info():
    """Telegram Information & OSINT"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ TELEGRAM INFORMATION ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Buscar usuario de Telegram")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Información de seguridad")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Privacidad en Telegram")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Detectar bots y canales")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            username = safe_input(ANSI_YELLOW + "\nUsuario Telegram (@username): " + ANSI_RESET).strip()
            if username:
                if not username.startswith("@"):
                    username = "@" + username
                print(ANSI_GREEN + f"\n[+] Enlace directo: https://t.me/{username}" + ANSI_RESET)
                print(ANSI_YELLOW + "[*] Puedes acceder directamente desde navegador web")
                print(ANSI_YELLOW + "[*] O buscar el usuario dentro de la aplicación")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_GREEN + "\n[+] INFORMACIÓN SOBRE TELEGRAM" + ANSI_RESET)
            info = [
                ("Encriptación", "Ofrece chats secretos con E2E"),
                ("Servidores", "Distribuidos globalmente"),
                ("Código abierto", "Clientes abiertos, servidores cerrados"),
                ("Grupos", "Hasta 200,000 miembros"),
                ("Canales", "Broadcast de uno a muchos (público)"),
                ("Bots", "Automatización via Telegram Bot API"),
            ]
            for feature, description in info:
                print(f"   • {feature}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_YELLOW + "\n[*] RECOMENDACIONES DE PRIVACIDAD" + ANSI_RESET)
            privacy_tips = [
                "1. Usa chats secretos para conversaciones sensibles",
                "2. Desactiva 'Last Seen' si lo prefieres privado",
                "3. Limita quién puede verte 'online'",
                "4. No agregues a desconocidos en grupos",
                "5. Revisa permisos de grupo regularmente",
                "6. Cuidado con links maliciosos en canales",
                "7. No actives ubicación en tiempo real",
                "8. Usa PIN para proteger la app",
                "9. Ten cuidado al compartir archivos",
                "10. Desactiva vista previa de fotos en chats",
            ]
            for tip in privacy_tips:
                print(f"   {tip}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_GREEN + "\n[+] IDENTIFICAR BOTS Y CANALES" + ANSI_RESET)
            indicators = [
                "Bots:",
                "  • Respuestas instantáneas y automáticas",
                "  • Comandos con / (ej: /start, /help)",
                "  • Nombre típicamente contiene 'bot'",
                "",
                "Canales verificados:",
                "  • Tienen marca azul (checkmark)",
                "  • Pertenecen a entidades públicas",
                "  • Mensaje solo de administradores",
                "",
                "Canales sospechosos:",
                "  • Piden dinero o datos personales",
                "  • Ofrecen cosas ilícitas",
                "  • Abundante spam o phishing",
            ]
            for indicator in indicators:
                print(f"   {indicator}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_web_crawl():
    """Web Crawling - Extracción de información de sitios"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ WEB CRAWLING ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Extraer enlaces de página")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Buscar archivos (robots.txt, sitemap)")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Extraer emails")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            url = safe_input(ANSI_YELLOW + "\nURL a rastrear: " + ANSI_RESET).strip()
            if url:
                print(ANSI_CYAN + "\n[*] Extrayendo enlaces..." + ANSI_RESET)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")
                        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
                        if links:
                            print(ANSI_GREEN + f"[+] {len(links)} enlaces encontrados" + ANSI_RESET)
                            for link in links[:15]:
                                print(f"  → {link}")
                        else:
                            print(ANSI_YELLOW + "[*] No se encontraron enlaces" + ANSI_RESET)
                except Exception as e:
                    print(ANSI_RED + f"[!] Error: {e}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            url = safe_input(ANSI_YELLOW + "\nDominio: " + ANSI_RESET).strip()
            if url:
                print(ANSI_GREEN + "\n[+] Archivos importantes:" + ANSI_RESET)
                files = [
                    "/robots.txt",
                    "/sitemap.xml",
                    "/.well-known/security.txt",
                    "/admin",
                    "/.git/config",
                    "/.env",
                ]
                for file in files:
                    print(f"  → https://{url}{file}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            url = safe_input(ANSI_YELLOW + "\nURL a analizar: " + ANSI_RESET).strip()
            if url:
                print(ANSI_CYAN + "\n[*] Buscando emails..." + ANSI_RESET)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")
                        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', html)
                        if emails:
                            unique_emails = list(set(emails))
                            print(ANSI_GREEN + f"[+] {len(unique_emails)} email(s) encontrado(s)" + ANSI_RESET)
                            for email in unique_emails[:10]:
                                print(f"  → {email}")
                        else:
                            print(ANSI_YELLOW + "[*] No se encontraron emails" + ANSI_RESET)
                except Exception as e:
                    print(ANSI_RED + f"[!] Error: {e}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_wireless_attack():
    """Wireless Security - Análisis y Hardening"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ WIRELESS SECURITY ASSESSMENT ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Analizar seguridad de red WiFi")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Ver interfaces de red")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Vulnerabilidades inalámbricas comunes")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            ssid = safe_input(ANSI_YELLOW + "\nNombre de red (SSID): " + ANSI_RESET).strip()
            encryption = safe_input(ANSI_YELLOW + "Encriptación (WEP/WPA/WPA2/WPA3): " + ANSI_RESET).strip()
            
            if ssid:
                analysis = analyze_wireless_security(ssid, encryption)
                print(ANSI_GREEN + f"\n[+] Análisis de seguridad para '{ssid}'" + ANSI_RESET)
                if analysis["vulnerabilities"]:
                    print(ANSI_RED + "[!] Vulnerabilidades encontradas:" + ANSI_RESET)
                    for vuln in analysis["vulnerabilities"]:
                        print(f"    ✗ {vuln}")
                if analysis["recommendations"]:
                    print(ANSI_YELLOW + "\n[*] Recomendaciones:" + ANSI_RESET)
                    for rec in analysis["recommendations"]:
                        print(f"    → {rec}")
                print(f"\n   [*] Puntuación de riesgo: {analysis['score']}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_YELLOW + "\n[*] Interfaces de red detectadas:" + ANSI_RESET)
            if platform.system() == "Windows":
                os.system("netsh wlan show interfaces 2>nul")
            else:
                os.system("iwconfig 2>/dev/null || nmcli device status")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_RED + "\n[!] VULNERABILIDADES INALÁMBRICAS COMUNES" + ANSI_RESET)
            vulns = {
                "WEP": "Encriptación obsoleta y débil",
                "WPA": "Vulnerable a ciertos ataques (KRACK)",
                "Sin encriptación": "Tráfico completamente expuesto",
                "WPS habilitado": "Vulnerable a ataques de fuerza bruta",
                "SSID broadcast": "Red visible aumenta vectores de ataque",
                "Contraseña débil": "Susceptible a diccionario",
                "Firmware desactualizado": "Vulnerabilidades conocidas",
            }
            for vuln, desc in vulns.items():
                print(f"   • {vuln}: {desc}")
            print(ANSI_GREEN + "\n[+] MEJORES PRÁCTICAS" + ANSI_RESET)
            practices = [
                "• Usa WPA2 o WPA3 como mínimo",
                "• Contraseña de 16+ caracteres (mayúsculas, números, símbolos)",
                "• Deshabilita WPS",
                "• Cambia SSID y contraseña default",
                "• Mantén firmware del router actualizado",
                "• Filtra por dirección MAC (opcional)",
                "• Oculta SSID si es posible",
                "• Usa contraseña para admin del router",
            ]
            for practice in practices:
                print(f"   {practice}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_free_proxy():
    """Free Proxy - Información y alternativas seguras"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ PROXY & ANONYMITY TOOLS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " Información sobre proxies")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Ventajas y desventajas")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Alternativas recomendadas")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Detectar tu IP real")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            print(ANSI_GREEN + "\n[+] TIPOS DE PROXIES" + ANSI_RESET)
            proxy_types = {
                "HTTP Proxy": "Funciona con HTTP/HTTPS, más básico",
                "SOCKS Proxy": "Más verstil, funciona con cualquier protocolo",
                "VPN": "Encripción completa, nivel OS",
                "Tor": "Red de anonimato, muy seguro pero lento",
                "I2P": "Red interna, mejor para privacidad de aplicación",
            }
            for ptype, description in proxy_types.items():
                print(f"   • {ptype}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_YELLOW + "\n[*] PROXIES GRATUITOS" + ANSI_RESET)
            print("   Ventajas:")
            print("      ✓ No costo")
            print("      ✓ Fáciles de usar")
            print("   Desventajas:")
            print("      ✗ Lentitud significativa")
            print("      ✗ Pueden ser más inseguros")
            print("      ✗ Mejor para logueo personal")
            print("      ✗ Riesgo de man-in-the-middle")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            print(ANSI_GREEN + "\n[+] ALTERNATIVAS RECOMENDADAS" + ANSI_RESET)
            alternatives = [
                ("Tor Browser", "Libre, código abierto, más seguro"),
                ("ProtonVPN", "Gratuito con limitaciones, confíable"),
                ("Windscribe VPN", "Gratuito, buena reputación"),
                ("Mullvad VPN", "Privado, sin logs, fácil usabilidad"),
                ("Perfect Privacy", "Premium pero muy seguro"),
            ]
            for name, description in alternatives:
                print(f"   • {name}: {description}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_YELLOW + "\n[*] CÓMO DETECTAR TU IP REAL:" + ANSI_RESET)
            print("   Estos servicios revelan tu IP real incluso con proxy:")
            print("   • Por WebRTC: leak.titor.in")
            print("   • Por DNS: dnsleaktest.com")
            print("   • IP general: whatsmyipaddress.com")
            print("   • Test completo: brow.sh")
            print("\n   Usa Tor Browser para mayor privacidad")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def menu_mix_tools():
    """Mix Tools - Herramientas variadas"""
    while True:
        print_header()
        print(ANSI_CYAN + "━━━━━ MIX TOOLS ━━━━━" + ANSI_RESET)
        print(ANSI_CYAN + "[1]" + ANSI_RESET + " DNS + HTTP headers")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + " Info local + red")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + " Generador MD5/SHA256")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + " Verificador de Base64")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + " Volver")
        
        choice = safe_input(ANSI_GREEN + "\nSelecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            domain = safe_input(ANSI_YELLOW + "\nDominio: " + ANSI_RESET).strip()
            if domain:
                print(ANSI_CYAN + "\n[*] DNS Enumeration..." + ANSI_RESET)
                records = dns_enumerate(domain)
                for rtype in ["A", "MX", "NS", "TXT"]:
                    vals = records.get(rtype, [])
                    if vals:
                        print(f"  {rtype}: {', '.join(vals[:3])}")
                
                print(ANSI_CYAN + "\n[*] HTTP Headers..." + ANSI_RESET)
                try:
                    req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "AleEthicalTools/2.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        print(ANSI_GREEN + "  Status: " + ANSI_RESET + str(resp.status))
                        for header, value in resp.headers.items():
                            if header.lower() in ["server", "content-type", "x-powered-by"]:
                                print(f"  {header}: {value}")
                except Exception as e:
                    print(ANSI_RED + f"  Error: {e}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "2":
            print(ANSI_GREEN + "\n[+] INFORMACIÓN LOCAL" + ANSI_RESET)
            print(f"  Hostname: {socket.gethostname()}")
            print(f"  Red Local: {detect_local_network()}")
            print(f"  IP Local: {socket.gethostbyname(socket.gethostname())}")
            print(ANSI_YELLOW + "\n[*] Información del sistema:" + ANSI_RESET)
            print(f"  Sistema: {platform.system()}")
            print(f"  Release: {platform.release()}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "3":
            text = safe_input(ANSI_YELLOW + "\nTexto a hashear: " + ANSI_RESET).strip()
            if text:
                print(ANSI_GREEN + "\n[+] Hashes generados:" + ANSI_RESET)
                print(f"  MD5:    {hashlib.md5(text.encode()).hexdigest()}")
                print(f"  SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
                print(f"  SHA512: {hashlib.sha512(text.encode()).hexdigest()}")
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "4":
            print(ANSI_YELLOW + "[*] Especifica operación:" + ANSI_RESET)
            print(ANSI_CYAN + "  [1] Codificar a Base64" + ANSI_RESET)
            print(ANSI_CYAN + "  [2] Decodificar Base64" + ANSI_RESET)
            op = safe_input(ANSI_GREEN + "Opción: " + ANSI_RESET).strip()
            
            if op == "1":
                text = safe_input(ANSI_YELLOW + "Texto a codificar: " + ANSI_RESET).strip()
                if text:
                    encoded = hashlib.sha256(text.encode()).hexdigest()
                    print(ANSI_GREEN + f"[+] Resultado: {encoded}" + ANSI_RESET)
            elif op == "2":
                try:
                    text = safe_input(ANSI_YELLOW + "Base64 a decodificar: " + ANSI_RESET).strip()
                    if text:
                        import base64
                        decoded = base64.b64decode(text).decode()
                        print(ANSI_GREEN + f"[+] Resultado: {decoded}" + ANSI_RESET)
                except Exception as e:
                    print(ANSI_RED + f"[!] Error: {e}" + ANSI_RESET)
            safe_input(ANSI_CYAN + "\nPresiona Enter..." + ANSI_RESET)
        
        elif choice == "5":
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

def main_menu():
    """Menú principal"""
    print_disclaimer()
    safe_input("Presiona Enter para continuar...")
    
    while True:
        print_header()
        print(ANSI_MAGENTA + ANSI_BOLD + "MENÚ PRINCIPAL".center(70) + ANSI_RESET)
        print()
        print(ANSI_CYAN + "[1]" + ANSI_RESET + "  Information Gathering")
        print(ANSI_CYAN + "[2]" + ANSI_RESET + "  Network Scanning")
        print(ANSI_CYAN + "[3]" + ANSI_RESET + "  Exploitation Tools")
        print(ANSI_CYAN + "[4]" + ANSI_RESET + "  Sniffing & Spoofing")
        print(ANSI_CYAN + "[5]" + ANSI_RESET + "  Web Attack Tools")
        print(ANSI_CYAN + "[6]" + ANSI_RESET + "  Cam Hacking Tools")
        print(ANSI_CYAN + "[7]" + ANSI_RESET + "  Remote Trojan RAT")
        print(ANSI_CYAN + "[8]" + ANSI_RESET + "  SQL Injection Tools")
        print(ANSI_CYAN + "[9]" + ANSI_RESET + "  Social Media Bruteforce")
        print(ANSI_CYAN + "[10]" + ANSI_RESET + " Social Media Finder")
        print(ANSI_CYAN + "[11]" + ANSI_RESET + " DDOS Attack Tools")
        print(ANSI_CYAN + "[12]" + ANSI_RESET + " Phishing Attack Tools")
        print(ANSI_CYAN + "[13]" + ANSI_RESET + " Hash Cracking Tools")
        print(ANSI_CYAN + "[14]" + ANSI_RESET + " Wordlist Generator")
        print(ANSI_CYAN + "[15]" + ANSI_RESET + " XSS Attack Tools")
        print(ANSI_CYAN + "[16]" + ANSI_RESET + " Discord Leaks")
        print(ANSI_CYAN + "[17]" + ANSI_RESET + " Telegram Info")
        print(ANSI_CYAN + "[18]" + ANSI_RESET + " Web Crawling")
        print(ANSI_CYAN + "[19]" + ANSI_RESET + " Wireless Attack Tools")
        print(ANSI_CYAN + "[20]" + ANSI_RESET + " Free Proxy")
        print(ANSI_CYAN + "[21]" + ANSI_RESET + " Mix Tools")
        print(ANSI_CYAN + "[22]" + ANSI_RESET + " Utilities")
        print(ANSI_CYAN + "[23]" + ANSI_RESET + " Professional Pentesting Tools")
        print(ANSI_CYAN + "[24]" + ANSI_RESET + " Salir")
        print()
        
        choice = safe_input(ANSI_GREEN + "Selecciona opción: " + ANSI_RESET).strip()
        
        if choice == "1":
            menu_info_gathering()
        elif choice == "2":
            menu_network_scanning()
        elif choice == "3":
            menu_exploitation_tools()
        elif choice == "4":
            menu_sniffing_spoofing()
        elif choice == "5":
            menu_web_attack()
        elif choice == "6":
            menu_cam_hacking()
        elif choice == "7":
            menu_remote_trojan()
        elif choice == "8":
            menu_sql_injection()
        elif choice == "9":
            menu_social_media_brute()
        elif choice == "10":
            menu_social_media_finder()
        elif choice == "11":
            menu_ddos_tools()
        elif choice == "12":
            menu_phishing_tools()
        elif choice == "13":
            menu_hash_cracking()
        elif choice == "14":
            menu_wordlist_gen()
        elif choice == "15":
            menu_xss_tools()
        elif choice == "16":
            menu_discord_leaks()
        elif choice == "17":
            menu_telegram_info()
        elif choice == "18":
            menu_web_crawl()
        elif choice == "19":
            menu_wireless_attack()
        elif choice == "20":
            menu_free_proxy()
        elif choice == "21":
            menu_mix_tools()
        elif choice == "22":
            menu_utils()
        elif choice == "23":
            menu_professional_tools()
        elif choice == "24":
            print(ANSI_GREEN + ANSI_BOLD + "\n[+] ¡Hasta luego!" + ANSI_RESET)
            logger.log("INFO", "AleEthicalTools cerrado")
            break
        else:
            print(ANSI_RED + "[!] Opción no válida" + ANSI_RESET)
            safe_input("Presiona Enter...")

if __name__ == "__main__":
    try:
        # Crear wordlists
        create_sample_wordlist()
        logger.log("INFO", "AleEthicalTools iniciado")
        main_menu()
    except KeyboardInterrupt:
        print(ANSI_RED + "\n[!] Interrupción del usuario" + ANSI_RESET)
        logger.log("INFO", "AleEthicalTools interrumpido por usuario")
    except Exception as e:
        print(ANSI_RED + f"\n[!] Error: {e}" + ANSI_RESET)
        logger.log("ERROR", f"Error: {e}")
