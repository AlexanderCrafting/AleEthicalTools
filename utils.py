

import logging
import os
import json
from datetime import datetime
from config import LOGS_DIR, REPORTS_DIR, LOG_FORMAT, LOG_DATE_FORMAT

class ScanLogger:
    
    def __init__(self, name="AleEthicalTools"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        
        log_file = os.path.join(LOGS_DIR, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log(self, level, message):
        if level == "DEBUG":
            self.logger.debug(message)
        elif level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)

class ReportGenerator:
    
    def __init__(self, scan_type, target):
        self.scan_type = scan_type
        self.target = target
        self.timestamp = datetime.now()
        self.results = {}
    
    def add_result(self, key, value):
        self.results[key] = value
    
    def generate_html_report(self, filename=None):
        if not filename:
            filename = f"{self.scan_type}_{self.target}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = os.path.join(REPORTS_DIR, filename)
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte AleEthicalTools - {self.scan_type}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        .section {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .metric {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-card .value {{ font-size: 2em; font-weight: bold; }}
        .metric-card .label {{ opacity: 0.9; margin-top: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        table th {{ background: #667eea; color: white; padding: 12px; text-align: left; }}
        table td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        table tr:hover {{ background: #f0f0f0; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Reporte de Auditoría Ética - AleEthicalTools</h1>
        <p><strong>Tipo de escaneo:</strong> {self.scan_type}</p>
        <p><strong>Objetivo:</strong> {self.target}</p>
        <p><strong>Fecha y hora:</strong> {self.timestamp.strftime('%d/%m/%Y %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>📋 Resumen de resultados</h2>
        <div class="metric">
                <div class="value">{value if isinstance(value, (int, str)) else len(value)}</div>
                <div class="label">{key}</div>
            </div>
    </div>
    
    <div class="section">
        <h2>📊 Detalles</h2>
        <pre style="background: #f9f9f9; padding: 15px; border-radius: 5px; overflow-x: auto;">"""
        
        for key, value in self.results.items():
            if isinstance(value, (list, dict)):
                html += f"{key}:\n{json.dumps(value, indent=2, ensure_ascii=False)}\n\n"
            else:
                html += f"{key}: {value}\n"
        
        html += """</pre>
    </div>
    
    <div class="section" style="background: #fff3cd; border-left: 5px solid #ffc107;">
        <h2>⚠️ Aviso Legal</h2>
        <p>Este reporte fue generado con AleEthicalTools para fines de auditoría ética autorizada solamente. 
        El usuario es responsable de asegurar que todas las pruebas fueron realizadas con consentimiento explícito</p>
    </div>
    
    <div class="footer">
        <p>AleEthicalTools v1.0.0 | Generado automáticamente | Para auditoría ética autorizada</p>
    </div>
</body>
</html>"""
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        return filepath
    
    def generate_json_report(self, filename=None):
        if not filename:
            filename = f"{self.scan_type}_{self.target}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(REPORTS_DIR, filename)
        
        report_data = {
            "metadata": {
                "tool": "AleEthicalTools",
                "version": "1.0.0",
                "timestamp": self.timestamp.isoformat(),
                "scan_type": self.scan_type,
                "target": self.target,
            },
            "results": self.results
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filepath

def create_sample_wordlist():
    from config import WORDLISTS_DIR
    
    wordlists = {
        "passwords_common.txt": [
            "password", "123456", "12345678", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty",
            "abc123", "password123", "admin123", "root", "toor",
        ],
        "usernames_common.txt": [
            "admin", "root", "user", "test", "guest",
            "administrator", "alexader", "alejandro", "alexa", "ale",
        ],
        "domains_common.txt": [
            "google.com", "facebook.com", "instagram.com", "twitter.com",
            "youtube.com", "linkedin.com", "gmail.com", "hotmail.com",
        ],
    }
    
    for filename, words in wordlists.items():
        filepath = os.path.join(WORDLISTS_DIR, filename)
        if not os.path.exists(filepath):
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(words))
