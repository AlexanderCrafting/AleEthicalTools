

import re
import hashlib
import json
from datetime import datetime

def check_password_strength(password):
    strength = {
        "score": 0,
        "rating": "Muy débil",
        "feedback": [],
    }
    
    if len(password) >= 8:
        strength["score"] += 1
    if len(password) >= 12:
        strength["score"] += 1
    if len(password) >= 16:
        strength["score"] += 1
    
    if re.search(r'[a-z]', password):
        strength["score"] += 1
    if re.search(r'[A-Z]', password):
        strength["score"] += 1
    if re.search(r'[0-9]', password):
        strength["score"] += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        strength["score"] += 1
    
    if strength["score"] <= 1:
        strength["rating"] = "Muy débil"
        strength["feedback"].append("Aumenta la longitud (mín 12 caracteres)")
    elif strength["score"] <= 3:
        strength["rating"] = "Débil"
        strength["feedback"].append("Mezcla mayúsculas, minúsculas y números")
    elif strength["score"] <= 5:
        strength["rating"] = "Moderada"
        strength["feedback"].append("Agrega caracteres especiales para mayor seguridad")
    elif strength["score"] <= 6:
        strength["rating"] = "Fuerte"
        strength["feedback"].append("Buena contraseña")
    else:
        strength["rating"] = "Muy fuerte"
        strength["feedback"].append("Contraseña excelente")
    
    return strength

def detect_phishing_indicators(email_text):
    indicators = {
        "high_risk": [],
        "medium_risk": [],
        "suspicious_links": [],
        "score": 0,
    }
    
    text_lower = email_text.lower()
    
    high_risk_keywords = [
        "verify your account",
        "confirm your password",
        "update billing",
        "unusual activity",
        "click here immediately",
        "act now",
        "limited time",
        "account will be closed",
    ]
    
    for keyword in high_risk_keywords:
        if keyword in text_lower:
            indicators["high_risk"].append(keyword)
            indicators["score"] += 2
    
    medium_risk_patterns = [
        (r'click (here|link|this)', "Click para confirmar"),
        (r'http://[^ \n]+', "URL sin HTTPS"),
        (r'dear (customer|user|member)', "Saludo genérico"),
    ]
    
    for pattern, description in medium_risk_patterns:
        if re.search(pattern, text_lower):
            indicators["medium_risk"].append(description)
            indicators["score"] += 1
    
    urls = re.findall(r'https?://[^\s\n]+', email_text)
    for url in urls:
        if 'http://' in url and not '127.0.0.1' in url and not 'localhost' in url:
            indicators["suspicious_links"].append(url)
            indicators["score"] += 1
    
    return indicators

def analyze_wireless_security(ssid, encryption=None):
    analysis = {
        "ssid": ssid,
        "encryption": encryption or "Desconocido",
        "vulnerabilities": [],
        "recommendations": [],
        "score": 0,
    }
    
    if ssid and ssid.lower() != "hidden":
        analysis["vulnerabilities"].append("SSID está siendo difundido (visible)")
        analysis["score"] += 1
    
    if ssid and "admin" in ssid.lower() or "router" in ssid.lower():
        analysis["vulnerabilities"].append("SSID contiene información del dispositivo")
        analysis["score"] += 1
    
    if not encryption or encryption.lower() in ["none", "open", "wep"]:
        analysis["vulnerabilities"].append("Sin encriptación o encriptación débil (WEP)")
        analysis["score"] += 3
        analysis["recommendations"].append("Cambia a WPA2 o WPA3")
    elif encryption.lower() == "wpa":
        analysis["vulnerabilities"].append("WPA es vulnerable a ciertos ataques")
        analysis["score"] += 2
        analysis["recommendations"].append("Actualiza a WPA2 o WPA3")
    elif encryption.lower() in ["wpa2", "wpa3"]:
        analysis["score"] -= 1  # Puntos negativos = más seguro
    
    analysis["recommendations"].extend([
        "Usa contraseña fuerte (16+ caracteres)",
        "Oculta el SSID (opcional)",
        "Habilita el filtro MAC",
        "Desactiva WPS",
        "Cambia contraseña default",
        "Actualiza firmware del router",
    ])
    
    return analysis

def check_port_security(port):
    port_info = {
        "port": port,
        "service": "Desconocido",
        "risk_level": "Bajo",
        "recommendations": [],
    }
    
    dangerous_ports = {
        21: ("FTP", "Alto", ["Usa SFTP o SSH en lugar de FTP"]),
        23: ("Telnet", "Alto", ["Usa SSH en lugar de Telnet"]),
        80: ("HTTP", "Medio", ["Usa HTTPS para datos sensibles"]),
        445: ("SMB", "Alto", ["Limita acceso a este puerto", "Requiere autenticación fuerte"]),
        3306: ("MySQL", "Alto", ["No expongas en Internet", "Usa firewall"]),
        3389: ("RDP", "Alto", ["Limita a IPs específicas", "Usa VPN"]),
        5432: ("PostgreSQL", "Alto", ["No expongas en Internet", "Usa firewall"]),
        27017: ("MongoDB", "Crítico", ["Requiere autenticación", "No expongas en Internet"]),
    }
    
    if port in dangerous_ports:
        port_info["service"], port_info["risk_level"], port_info["recommendations"] = dangerous_ports[port]
    
    return port_info

def analyze_url_safety(url):
    analysis = {
        "url": url,
        "warnings": [],
        "score": 0,
        "safe": True,
    }
    
    if not url.startswith("https://"):
        if url.startswith("http://"):
            analysis["warnings"].append("URL usa HTTP inseguro (sin encriptación)")
            analysis["score"] += 1
        else:
            analysis["warnings"].append("Protocolo no identificado")
            analysis["score"] += 2
    
    suspicious_patterns = [
        (r'%[0-9a-f]{2}', "Contiene codificación URL (puede ocultar contenido)"),
        (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "Usa IP en lugar de dominio"),
        (r'@', "Contiene símbolo @ (puede ser phishing)"),
        (r'-+', "Contiene múltiples guiones (typosquatting)"),
    ]
    
    for pattern, warning in suspicious_patterns:
        if re.search(pattern, url):
            analysis["warnings"].append(warning)
            analysis["score"] += 1
    
    if analysis["score"] > 2:
        analysis["safe"] = False
    
    return analysis

def generate_security_report(data_dict):
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {},
        "details": data_dict,
        "total_issues": 0,
    }
    
    for key, value in data_dict.items():
        if isinstance(value, dict):
            if "score" in value:
                report["total_issues"] += value.get("score", 0)
            if "vulnerabilities" in value:
                report["total_issues"] += len(value.get("vulnerabilities", []))
            if "warnings" in value:
                report["total_issues"] += len(value.get("warnings", []))
    
    return report

def check_common_vulnerabilities(target_info):
    vulnerabilities = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    
    if isinstance(target_info, dict):
        defaults = {
            "admin/admin": "Credenciales default",
            "admin/12345": "Credenciales débiles comunes",
            "root/root": "Credenciales default",
        }
        
        vulnerabilities["critical"] = [
            "Encriptación débil (WEP, DES)",
            "Sin autenticación",
            "Puertos peligrosos expuestos",
        ]
        
        vulnerabilities["high"] = [
            "Credenciales default",
            "HTTP sin HTTPS",
            "SQL injection posible",
        ]
        
        vulnerabilities["medium"] = [
            "Información excesiva en headers",
            "CORS mal configurado",
            "Sesiones sin protección",
        ]
        
        vulnerabilities["low"] = [
            "Información de versión expuesta",
            "Directorios indexables",
            "Comentarios en código",
        ]
    
    return vulnerabilities

def simulate_brute_force_difficulty(password_char_set_size, password_length):
    import math
    
    total_combinations = password_char_set_size ** password_length
    
    
    seconds_needed = (total_combinations / 2) / 1_000_000
    
    breakdown = {
        "total_combinations": total_combinations,
        "combinations_per_second": 1_000_000,
        "seconds_needed": seconds_needed,
        "minutes": seconds_needed / 60,
        "hours": seconds_needed / 3600,
        "days": seconds_needed / 86400,
        "years": seconds_needed / (86400 * 365),
    }
    
    return breakdown

def detect_default_credentials():
    return {
        "Router TP-Link": {"user": "admin", "pass": "admin"},
        "Router D-Link": {"user": "admin", "pass": "admin"},
        "Arduino": {"user": "admin", "pass": "admin"},
        "MySQL": {"user": "root", "pass": ""},
        "PostgreSQL": {"user": "postgres", "pass": "postgres"},
        "Oracle": {"user": "sys", "pass": "change_on_install"},
    }
