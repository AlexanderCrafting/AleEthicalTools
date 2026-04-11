# GUÍA RÁPIDA DE INICIO - AleEthicalTools v1.0.0

## ⚡ Inicio Rápido (2 minutos)

### Windows
1. Doble clic en `run.bat`
2. Espera a que se cargue
3. Selecciona una opción del menú

### Linux/macOS
```bash
chmod +x run.sh
./run.sh
```

### Línea de Comandos
```bash
python main.py
```

---

## 📖 Ejemplo: Escanear una red

### Paso 1: Seleccionar menú
```
[2] Network Scanning (Escaneo de red)
```

### Paso 2: Elegir tipo de escaneo
```
[3] Escaneo rápido red local
```

### Resultado
```
[+] Red detectada: 192.168.1.0/24
[*] Escaneando hosts...

[+] 192.168.1.1    | gateway           | 2ms
[+] 192.168.1.10   | servidor          | 5ms
[+] 192.168.1.50   | laptop            | 8ms

[*] Escaneo completado en 12.45s
[+] 3 host(s) activos de 254
[+] Reporte guardado: reports/ping_sweep_...html
```

---

## 🎯 Ejemplo: Obtener información de dominio

### Paso 1: Seleccionar información
```
[1] Information Gathering (Recopilación)
[1] DNS Lookup avanzado
```

### Paso 2: Ingresar dominio
```
Dominio: google.com
```

### Resultado
```
A Records:
  → 142.251.32.46
  → 142.251.32.14

MX Records:
  → 10 smtp.google.com
  → 20 smtp02.google.com

NS Records:
  → ns1.google.com
  → ns2.google.com
```

---

## 🛠️ Instalación de Dependencias

### Opción 1: Automática
```bash
python install_deps.py
```

### Opción 2: Manual
```bash
pip install -r requirements.txt
```

### Módulos principales
- `dnspython`: DNS enumeration
- `beautifulsoup4`: Web parsing
- `cryptography`: SSL/TLS analysis
- `requests`: HTTP requests mejorados

---

## 📋 Estructura de Menús

```
AleEthicalTools v2.0.0
│
├─ [1] Information Gathering
│  ├─ DNS Lookup avanzado
│  ├─ Información de IP
│  ├─ WHOIS Lookup
│  ├─ Headers HTTP
│  ├─ Escanear rutas
│  └─ Certificado SSL
│
├─ [2] Network Scanning
│  ├─ Escaneo ping
│  ├─ Escaneo de puertos
│  ├─ Escaneo red local
│  └─ Banner grabbing
│
├─ [3] Web Tools
│  ├─ Extraer emails
│  ├─ Extraer URLs
│  ├─ Extraer IPs
│  └─ Extraer hashes
│
├─ [4] Utilities
│  ├─ Generador de contraseñas
│  ├─ Hash generator
│  └─ Información del sistema
│
└─ [5] Salir
```

---

## 📊 Donde se guardan los resultados

```
PROYECTOALE/
├─ logs/           → Logs de auditoría (automático)
├─ reports/        → Reportes HTML/JSON
├─ wordlists/      → Wordlists de ejemplo
└─ data/           → Datos almacenados
```

### Acceder a reportes
1. Los reportes se guardan automáticamente
2. Ubicación: `reports/` folder
3. Formato: HTML (navegador) + JSON (análisis)

---

## 🔍 Casos de Uso Comunes

### Auditoría de servidor propio
```
1. Network Scanning → Escaneo de puertos
2. Ingresar IP: 192.168.1.10
3. Rango: 1-65535
4. Obtener lista de puertos abiertos
```

### Análisis de dominio
```
1. Information Gathering → DNS Lookup
2. Ingresar dominio
3. Obtener registros DNS completos
```

### Búsqueda de información en texto
```
1. Web Tools → Extraer emails/IPs/URLs
2. Pegar contenido
3. Obtener lista filtrada
```

### Generar contraseña segura
```
1. Utilities → Generador de contraseñas
2. Elegir longitud
3. Copiar contraseña generada
```

---

## ⚠️ Recordar

- **Solo uso ético**: Lee el disclaimer al iniciar
- **Sé autorizado**: No escanees sistemas ajenos sin permiso
- **Respeta la ley**: El uso ilegal tiene consecuencias graves
- **Copia permisos**: Documenta autorizaciones para escaneos

---

## 🐛 Solucionar problemas

### Python no encontrado
```bash
# Windows: Instala desde python.org
# Linux: apt-get install python3
# macOS: brew install python3
```

### Módulos faltantes
```bash
pip install dnspython beautifulsoup4 cryptography
```

### Permiso denegado en Windows
```
→ Ejecuta como administrador (clic derecho → Ejecutar como administrador)
```

### Puerto bloqueado
```
→ Algunos escaneos fallan detrás de firewalls
→ Verifica tu conexión de red
```

---

## 📞 Próximos Pasos

1. Lee el [README.md](README.md) completo
2. Revisa los ejemplos en [README.md](README.md)
3. Explora todas las funciones
4. Genera reportes en HTML
5. Integra con herramientas externas via JSON

---

**Documentacion y comentarios hechos por IA**

v1.0.0 | Alejandro Rosas | 2026
