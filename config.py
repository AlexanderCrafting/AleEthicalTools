import os
from datetime import datetime

APP_NAME = "AleEthicalTools"
VERSION = "1.0.0"
AUTHOR = "Alexander Crafting"
DESCRIPTION = "Suite profesional de auditoria etica y pruebas de penetracion autorizadas"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
DATA_DIR = os.path.join(BASE_DIR, "data")

for directory in [LOGS_DIR, REPORTS_DIR, WORDLISTS_DIR, DATA_DIR]:
    os.makedirs(directory, exist_ok=True)

TIMEOUT_PING = 2
TIMEOUT_PORT = 1.5
TIMEOUT_HTTP = 10
TIMEOUT_WHOIS = 10

MAX_THREADS = 200
MAX_HOSTS_SCAN = 256
MAX_PORTS_BATCH = 1000

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

ETHICAL_DISCLAIMER = "This tool is for authorized security testing only. Unauthorized access is illegal."

COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    194: "irc",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-proxy",
    27017: "mongodb",
    5984: "couchdb",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15",
]
