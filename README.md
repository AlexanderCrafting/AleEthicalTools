# AleEthicalTools v2.0.0 - Suite Profesional de Auditoría Ética

## 📋 Descripción

**AleEthicalTools** es una suite **completa y profesional** de auditoría ética diseñada para:
- ✅ Auditoría de seguridad en sistemas autorizados
- ✅ Investigación académica y educativa
- ✅ Inteligencia de fuentes abiertas (OSINT)
- ✅ Pruebas éticas de penetración (Ethical Hacking)
- ✅ Análisis de vulnerabilidades
- ✅ Reconocimiento de objetivos

**⚖️ IMPORTANTE**: Esta herramienta está diseñada ÚNICAMENTE para uso ético y autorizado. El uso no autorizado es ILEGAL.

## 📦 Estructura del Proyecto

```
PROYECTOALE/
├── main.py                    # Menú principal (24 opciones)
├── config.py                  # Configuración global
├── utils.py                   # Logging y reportes
├── network_tools.py           # 15+ funciones de red
├── security_tools.py          # 8 herramientas de seguridad
├── osint_tools.py            # OSINT y búsqueda de usuarios
├── pentest_tools.py          # BD de 10 herramientas profesionales
├── pentest_menu.py           # Menú interactivo de pentesting
├── requirements.txt           # Dependencias Python
├── wordlists/                # Diccionarios de fuerza bruta
├── logs/                     # Logs automáticos
├── reports/                  # Reportes HTML/JSON
└── data/                     # Datos almacenados
```

## 🚀 Instalación y Uso

### Requisitos
- Python 3.7+
- Windows, Linux o macOS
- Conexión a Internet (para algunas funciones OSINT)

### Instalación Rápida

```bash
cd PROYECTOALE
python main.py
```

### Dependencias Opcionales

```bash
pip install dnspython        # DNS avanzado
pip install cryptography     # SSL/TLS
pip install beautifulsoup4   # Web scraping
```

## 🎯 Características Principales (24 Opciones)

### 1️⃣ **Information Gathering** (Recopilación)
- DNS Lookup avanzado (A, AAAA, CNAME, MX, NS, TXT)
- Información detallada de IP
- WHOIS Lookup
- Análisis de HTTP headers y tecnologías
- Escaneo de rutas comunes
- Certificado SSL/TLS
- Enumeración de subdominios

### 2️⃣ **Network Scanning** (Escaneo de Red)
- Ping Sweep con multithreading
- Escaneo de puertos TCP
- Escaneo rápido de red local
- Banner Grabbing
- Detección de servicios

### 3️⃣ **Exploitation Tools**
- Port scanning avanzado
- Ping scanning
- Banner grabbing
- Envío de paquetes UDP

### 4️⃣ **Sniffing & Spoofing**
- Información de interfaz de red
- Tabla ARP
- Información de red local

### 5️⃣ **Web Attack Tools**
- Búsqueda de formularios
- Búsqueda de enlaces
- Escaneo de rutas comunes

### 6️⃣ **Cam Hacking** (Seguridad de Cámaras IP)
- Puertos comunes
- Credenciales por defecto educativas
- Vulnerabilidades comunes
- Recomendaciones de hardening

### 7️⃣ **Remote Trojan RAT** (Información educativa)
- Medidas defensivas
- Detección de procesos
- Monitoreo de conexiones

### 8️⃣ **SQL Injection** (Detección & Defensa)
- Payloads educacionales
- Métodos de protección
- Indicadores de vulnerabilidad

### 9️⃣ **Social Media Bruteforce** (Búsqueda de Usernames)
- Verificar disponibilidad de username
- Generar variaciones automáticas
- Búsqueda en múltiples plataformas

### 🔟 **Social Media Finder** (OSINT Real)
- **Búsqueda en GitHub**: Devuelve nombre, repos, followers (API real)
- **Búsqueda en Reddit**: Karma y perfil (API real)
- **Búsqueda en Twitter**: Verificación de existencia
- **Búsqueda en Instagram**: Verificación de perfil
- **Verificar Data Breaches**: Have I Been Pwned API
- **Búsqueda inversa de email**: Servicios públicos
- **Perfil OSINT Completo**: Recopilación multi-plataforma

### 1️⃣1️⃣ **DDOS Detection & Defense** (Defensa, No Ataque)
- Estrategias de mitigación
- Análisis de tráfico
- Protecciones recomendadas

### 1️⃣2️⃣ **Phishing Detection** (Detección & Prevención)
- Análisis de emails sospechosos
- Verificación de URLs maliciosas
- Indicadores de phishing

### 1️⃣3️⃣ **Hash Cracking & Password Security**
- Análisis de fortaleza de contraseña
- Cálculo de dificultad de fuerza bruta
- Evaluación educacional

### 1️⃣4️⃣ **Wordlist Generator**
- Wordlist secuencial
- Variaciones automáticas
- Usuarios comunes en sistemas
- Patrones de password comunes

### 1️⃣5️⃣ **XSS Detection** (Detección & Prevención)
- Tipos de XSS (Stored, Reflected, DOM-based, Blind)
- Payloads educacionales
- Métodos de prevención
- Indicadores de vulnerabilidad

### 1️⃣6️⃣ **Discord Leaks**
- Información educativa sobre seguridad

### 1️⃣7️⃣ **Telegram Info** (OSINT)
- Búsqueda de usuarios
- Información de seguridad
- Recomendaciones de privacidad
- Detección de bots y canales

### 1️⃣8️⃣ **Web Crawling** (Extracción de Contenido)
- Extracción de enlaces
- Búsqueda de archivos importantes
- Extracción de emails
- Rastreo de información

### 1️⃣9️⃣ **Wireless Security** (Evaluación de WiFi)
- Análisis de seguridad WiFi
- Vulnerabilidades inalámbricas
- Recomendaciones de hardening

### 2️⃣0️⃣ **Free Proxy & Anonymity**
- Información sobre proxies
- Alternativas recomendadas
- Herramientas de privacidad

### 2️⃣1️⃣ **Mix Tools** (Herramientas Variadas)
- DNS + HTTP headers
- Info local + red
- Generador de hashes (MD5, SHA256, SHA512)
- Codificador/Decodificador Base64

### 2️⃣2️⃣ **Utilities** (Utilidades)
- Generador de contraseñas fuertes
- Generador de hashes
- Información del sistema

### 2️⃣3️⃣ **Professional Pentesting Tools** ⭐ NUEVO
Referencia de 10 herramientas profesionales con guía completa:
- **Metasploit Framework**: Framework de explotación
- **Nmap**: Scanner de puertos
- **Burp Suite**: Web app testing
- **Wireshark**: Análisis de tráfico
- **Hydra**: Bruteforce de credenciales
- **John the Ripper**: Hash cracking
- **Hashcat**: GPU-based cracking
- **SQLMap**: SQL injection testing
- **Nikto**: Web scanner
- **Aircrack-ng**: WiFi auditing

Con: Descripción, instalación, comandos, casos de uso, nivel de riesgo, ruta de aprendizaje

### 2️⃣4️⃣ **Salir**
- Cierra la aplicación

## 🏗️ Módulos Principales

### 📄 main.py
- Menú principal interactivo (24 opciones)
- Gestor de flujo de ejecución
- Integración de todos los módulos

### 🔧 config.py
- Configuración global centralizada
- Servicios y puertos comunes
- Timeouts y límites
- User agents

### 📊 utils.py
- ScanLogger: Logging centralizado
- ReportGenerator: Reportes HTML/JSON
- Generación de wordlists

### 🌐 network_tools.py (15+ funciones)
- IP info lookup
- SSL certificate analysis
- DNS enumeration
- Banner grabbing
- Port scanning
- HTTP response analysis
- WHOIS lookup

### 🔐 security_tools.py (8 funciones)
- Password strength checker
- Phishing detection
- Wireless security analysis
- Port security check
- URL safety analysis
- Vulnerability detection
- Brute force simulator
- Default credentials finder

### 🔍 osint_tools.py (10 funciones - REAL)
- GitHub user search (API real)
- Reddit user search (API real)
- Twitter verification
- Instagram verification
- Email breach checking (HIBP API)
- Reverse email lookup
- Subdomain enumeration
- Domain availability check
- LinkedIn profile builder
- Complete OSINT profiling

### 🛡️ pentest_tools.py
- Base de datos de 10 herramientas profesionales
- Información de instalación por SO
- Comandos de referencia
- Casos de uso
- Pautas legales

### 📋 pentest_menu.py
- Menú interactivo de herramientas profesionales
- Búsqueda por categoría
- Learning path completo
- Pautas legales y éticas

## 📈 Características Técnicas

### Rendimiento
- Threading: Hasta 200 hilos concurrentes
- Escaneo de puertos: 100+ puertos/segundo
- Network detection: Auto-detección de red local
- Multiple protocols: TCP, UDP, ICMP, DNS

### Seguridad
- Logging completo: Todas las acciones registradas
- Error handling: Manejo robusto de excepciones
- Input validation: Validación de todas las entradas
- Timeout management: Prevención de bloqueos

### Reportes
- HTML: Reportes profesionales formateados
- JSON: Exportación para integración
- Timestamps: Auditoría completa
- Resultados: Detalle de hallazgos

### OSINT (Real)
- APIs públicas: GitHub, Reddit, Have I Been Pwned
- Búsqueda multi-plataforma: 9+ plataformas
- Enumeración de subdominios: 15 subdominios comunes
- Email breach detection: Verificación de data breaches

## 📝 Logs

Todos los eventos se registran en `logs/`:
- Escaneos ejecutados
- Resultados encontrados
- Errores y advertencias
- Timestamps completos

## 🔒 Descargo de Responsabilidad

```
╔════════════════════════════════════════════════════════════════╗
║           DESCARGO DE RESPONSABILIDAD IMPORTANTE              ║
║                                                                ║
║ AleEthicalTools es una suite de auditoría ética profesional   ║
║ diseñada ÚNICAMENTE para:                                    ║
║                                                                ║
║ • Pruebas en sistemas propios o autorizados                   ║
║ • Investigación académica y educativa                         ║
║ • Auditoría de seguridad con consentimiento                   ║
║ • Investigación de ciberseguridad ética                       ║
║                                                                ║
║ El uso NO AUTORIZADO de esta herramienta es ILEGAL y puede    ║
║ resultar en consecuencias legales graves.                     ║
║                                                                ║
║ El usuario asume toda responsabilidad por sus acciones.       ║
║ ════════════════════════════════════════════════════════════  ║
╚════════════════════════════════════════════════════════════════╝
```

## 📚 Ejemplos de Uso

### Ejemplo 1: Escaneo de Red Local
```
1. Seleccionar "Network Scanning"
2. Seleccionar "Escaneo rápido red local"
3. Se detectará automáticamente y escaneará los primeros 100 hosts
```

### Ejemplo 2: Análisis de Dominio
```
1. Seleccionar "Information Gathering"
2. Seleccionar "DNS Lookup avanzado"
3. Ingresar dominio (ej: google.com)
4. Obtener registros DNS completos
```

### Ejemplo 3: Escaneo de Puertos Específico
```
1. Seleccionar "Network Scanning"
2. Seleccionar "Escaneo de puertos"
3. Ingresar IP objetivo
4. Ingresar rango (ej: 1-1000)
5. Obtener reporte HTML con resultados
```

## � Descargo de Responsabilidad Completo

```
╔═══════════════════════════════════════════════════════════════╗
║         DESCARGO DE RESPONSABILIDAD - LEE COMPLETAMENTE      ║
║                                                               ║
║ AleEthicalTools es una herramienta profesional de auditoría   ║
║ ética para USO AUTORIZADO ÚNICAMENTE.                              ║
║                                                               ║
║ USO PERMITIDO:                                                ║
║  ✓ Pruebas en sistemas que posees                            ║
║  ✓ Auditoría con consentimiento escrito (ROE)                ║
║  ✓ Investigación académica y educativa                       ║
║  ✓ Testing de seguridad autorizado                           ║
║                                                               ║
║ USO PROHIBIDO:                                                ║
║  ✗ Acceso no autorizado a sistemas                           ║
║  ✗ Interceptación de datos sin consentimiento                ║
║  ✗ Testing sin documentación de autorización                 ║
║  ✗ Cualquier actividad ilegal                                ║
║                                                               ║
║ CONSECUENCIAS LEGALES:                                        ║
║  • Violación del CFAA (USA)                                  ║
║  • Violación del RCEP (México)                               ║
║  • Leyes cibernéticas locales                                ║
║  • Penas de cárcel y multas                                  ║
║                                                               ║
║ EL USUARIO ASUME TOTAL RESPONSABILIDAD POR SUS ACCIONES      ║
║═══════════════════════════════════════════════════════════════║
```

## 📚 Ejemplos de Uso Reales

### Ejemplo 1: OSINT Multi-plataforma
```
1. Seleccionar [10] Social Media Finder
2. Seleccionar [7] Perfil OSINT completo
3. Ingresar username (ej: github_user)
4. Obtener resultados de GitHub (repos, followers), Reddit (karma, created)
5. Reportes en HTML/JSON
```

### Ejemplo 2: Analizar Dominio Completo
```
1. Seleccionar [1] Information Gathering
2. Ejecutar DNS Lookup, WHOIS, SSL info
3. Enumerar subdominios
4. Escanear puertos comunes
5. Generar reporte de seguridad
```

### Ejemplo 3: Pentesting Profesional
```
1. Seleccionar [23] Professional Pentesting Tools
2. Seleccionar [1] Browse tools by category
3. Aprender instalación y comandos de Metasploit, Nmap, Burp Suite
4. Estudiar learning path desde básico a avanzado
5. Revisar pautas legales antes de usar
```

## 🎓 Ruta de Aprendizaje Recomendada

### Básico (Semana 1-2)
1. DNS fundamentales
2. TCP/IP basics
3. HTTP protocol
4. Usar Nmap básico
5. Wireshark fundamentals

### Intermedio (Semana 3-4)
1. OWASP Top 10
2. Web vulnerabilities (SQL, XSS)
3. Burp Suite basics
4. OSINT techniques
5. Social engineering awareness

### Avanzado (Semana 5+)
1. Metasploit Framework
2. Post-exploitation
3. Network pivoting
4. Hash cracking
5. Wireless security

## ⚡ Quick Start

```bash
# 1. Descargar o clonar
git clone <repo-url>
cd PROYECTOALE

# 2. Instalar dependencias (opcional)
pip install -r requirements.txt

# 3. Ejecutar
python main.py

# 4. Seleccionar opción del menú
# Ejemplo: [1] para Information Gathering
```

## ✅ Validación y Testing

Todos los módulos han sido validados:
- ✅ Syntax verification: py_compile
- ✅ OSINT APIs: GitHub, Reddit, HIBP (real funcional)
- ✅ Threading: Hasta 200 hilos concurrentes
- ✅ Reportes: HTML y JSON generación
- ✅ Logging: Auditoría completa

## 📞 Características Clave

- **24 opciones de menú**: Completa cobertura de técnicas
- **OSINT Real**: APIs públicas (GitHub, Reddit con datos reales)
- **10 herramientas profesionales**: Metasploit, Nmap, Burp Suite, etc.
- **Ethical focus**: Detección y defensa, no ataque
- **Multi-threading**: Rendimiento optimizado
- **Reportes automáticos**: HTML y JSON formateados
- **Logging auditable**: Trazabilidad completa
- **Pautas legales**: Prominentes y claras

## 🔒 Características de Seguridad

- Validación de entrada en todos los campos
- Manejo robusto de errores
- Timeouts para prevención de bloqueos
- Logging centralizado de todas las acciones
- Descargo de responsabilidad prominente
- Pautas éticas integradas

---

**Versión**: 2.0.0  
**Author**: Alexander Crafting  
**Last Updated**: April 2026  
**Status**: Production Ready ✅  
**License**: Ethical Auditing & Education
