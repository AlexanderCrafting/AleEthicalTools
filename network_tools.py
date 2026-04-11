

import socket
import struct
import urllib.request
import urllib.parse
import urllib.error
import re
import ssl
import hashlib
from datetime import datetime

def get_ip_info(ip):
    info = {
        "ip": ip,
        "hostname": None,
        "country": None,
        "isp": None,
        "type": None,
        "error": None,
    }
    
    try:
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            info["hostname"] = "N/A"
        
        try:
            ip_addr = socket.inet_aton(ip)
            ip_int = struct.unpack("!I", ip_addr)[0]
            
            if ip_int >= 167772160 and ip_int <= 184549375:
                info["type"] = "Privada (Clase A)"
            elif ip_int >= 2886729728 and ip_int <= 2887778303:
                info["type"] = "Privada (Clase B)"
            elif ip_int >= 3232235520 and ip_int <= 3232301055:
                info["type"] = "Privada (Clase C)"
            elif ip_int >= 2130706432 and ip_int <= 2147483647:
                info["type"] = "Loopback"
            else:
                info["type"] = "Pública"
        except Exception as e:
            info["error"] = str(e)
    
    except Exception as e:
        info["error"] = str(e)
    
    return info

def check_port_service(port):
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP Proxy",
        27017: "MongoDB",
    }
    return services.get(port, "Desconocido")

def extract_emails(text):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(pattern, text)

def extract_urls(text):
    pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
    return re.findall(pattern, text)

def extract_ips(text):
    pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    return re.findall(pattern, text)

def extract_hashes(text):
    hashes = {
        "MD5": re.findall(r'\b[a-fA-F0-9]{32}\b', text),
        "SHA1": re.findall(r'\b[a-fA-F0-9]{40}\b', text),
        "SHA256": re.findall(r'\b[a-fA-F0-9]{64}\b', text),
    }
    return {k: v for k, v in hashes.items() if v}

def get_ssl_cert_info(hostname):
    cert_info = {
        "hostname": hostname,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "version": None,
        "serial": None,
        "error": None,
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    try:
                        cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    except:
                        cert_info["subject"] = str(cert.get("subject", "N/A"))
                    
                    try:
                        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    except:
                        cert_info["issuer"] = str(cert.get("issuer", "N/A"))
                    
                    cert_info["valid_from"] = cert.get("notBefore", "N/A")
                    cert_info["valid_until"] = cert.get("notAfter", "N/A")
                    cert_info["version"] = cert.get("version", "N/A")
                else:
                    cert_info["error"] = "No certificate found"
    except ssl.SSLError as e:
        cert_info["error"] = f"SSL Error: {str(e)}"
    except socket.timeout:
        cert_info["error"] = "Connection timeout"
    except socket.gaierror as e:
        cert_info["error"] = f"DNS resolution failed: {str(e)}"
    except Exception as e:
        cert_info["error"] = str(e)
    
    return cert_info

def analyze_http_response(url, timeout=10):
    parsed = urllib.parse.urlparse(url, scheme="http")
    if not parsed.netloc:
        parsed = urllib.parse.urlparse("http://" + url)
    
    analysis = {
        "url": url,
        "status_code": None,
        "headers": {},
        "technologies": [],
        "content_type": None,
        "server": None,
        "error": None,
    }
    
    try:
        request = urllib.request.Request(
            parsed.geturl(),
            headers={"User-Agent": "AleEthicalTools/2.0"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            analysis["status_code"] = response.status
            
            headers_dict = {}
            for header, value in response.getheaders():
                headers_dict[header] = value
                analysis["headers"][header] = value
            
            if "Server" in headers_dict:
                server = headers_dict["Server"]
                analysis["server"] = server
                analysis["technologies"].append(f"Server: {server}")
            
            if "X-Powered-By" in headers_dict:
                analysis["technologies"].append(f"Framework: {headers_dict['X-Powered-By']}")
            
            if "X-AspNet-Version" in headers_dict:
                analysis["technologies"].append(f"ASP.NET: {headers_dict['X-AspNet-Version']}")
            
            if "Content-Type" in headers_dict:
                analysis["content_type"] = headers_dict["Content-Type"]
            
            for key in ["X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]:
                if key in headers_dict:
                    analysis["technologies"].append(f"Security: {key}")
    
    except urllib.error.HTTPError as e:
        analysis["status_code"] = e.code
        analysis["error"] = f"HTTP Error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        if "getaddrinfo failed" in str(e.reason) or "Name or service not known" in str(e.reason):
            analysis["error"] = f"DNS resolution failed for '{parsed.netloc}'"
        else:
            analysis["error"] = f"URL Error: {str(e.reason)}"
    except socket.gaierror as e:
        analysis["error"] = f"DNS resolution failed: {str(e)}"
    except socket.timeout:
        analysis["error"] = "Connection timeout (server not responding)"
    except ConnectionRefusedError:
        analysis["error"] = f"Connection refused by {parsed.netloc}"
    except ConnectionResetError:
        analysis["error"] = "Connection reset by server"
    except Exception as e:
        analysis["error"] = f"Error: {type(e).__name__}: {str(e)}"
    
    return analysis

def dns_enumerate(domain):
    records = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "error": None,
    }
    
    try:
        import dns.resolver
        from dns.rdatatype import RdataType
        
        for rdtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rdtype)
                records[rdtype] = [str(rr) for rr in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
        
        return records
    
    except ImportError:
        try:
            records["A"] = [socket.gethostbyname(domain)]
        except socket.gaierror as e:
            records["error"] = f"DNS lookup failed: {str(e)}"
        except Exception as e:
            records["error"] = f"Error: {str(e)}"
        
        try:
            ip = records["A"][0] if records["A"] else None
            if ip:
                hostname = socket.gethostbyaddr(ip)[0]
                records["CNAME"] = [hostname]
        except:
            pass
        
        return records
    
    except Exception as e:
        records["error"] = f"DNS enumeration failed: {str(e)}"
        return records


def whois_lookup(query):
    query = query.strip()
    
    if query.startswith("http://") or query.startswith("https://"):
        parsed = urllib.parse.urlparse(query)
        query = parsed.hostname or query
    
    whois_info = {
        "query": query,
        "server": "whois.iana.org",
        "result": None,
        "error": None,
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(("whois.iana.org", 43))
            sock.sendall((query + "\r\n").encode("utf-8"))
            
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            
            whois_info["result"] = response.decode("utf-8", errors="ignore")
            
    except socket.timeout:
        whois_info["error"] = "Connection timeout (whois.iana.org)"
    except socket.gaierror:
        whois_info["error"] = "DNS resolution failed for whois.iana.org"
    except ConnectionRefusedError:
        whois_info["error"] = "Connection refused by whois server"
    except Exception as e:
        whois_info["error"] = str(e)
    
    return whois_info

def banner_grab(host, port, timeout=5):
    banner_info = {
        "host": host,
        "port": port,
        "banner": None,
        "error": None,
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((host, port))
        
        if result == 0:
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                banner_info["banner"] = banner if banner else "(Empty banner)"
            except socket.timeout:
                banner_info["banner"] = "(Timeout reading banner)"
            except Exception as e:
                banner_info["error"] = f"Error reading banner: {str(e)}"
        else:
            banner_info["error"] = "Port is closed or unreachable"
        
        sock.close()
    
    except socket.gaierror:
        banner_info["error"] = "DNS resolution failed"
    except socket.timeout:
        banner_info["error"] = "Connection timeout"
    except Exception as e:
        banner_info["error"] = str(e)
    
    return banner_info

def scan_common_paths(url, paths=None):
    if paths is None:
        paths = [
            "/", "/admin", "/adm", "/administrator", "/panel",
            "/wp-admin", "/cpanel", "/login", "/signin", "/account",
            "/config", "/settings", "/console", "/api",
            "/.git", "/.env", "/.htaccess", "/robots.txt", 
            "/sitemap.xml", "/backup", "/sql", "/database",
            "/uploads", "/files", "/download", "/public",
            "/admin.php", "/login.php", "/index.html",
            "/web.config", "/app.config", "/appsettings.json",
        ]
    
    accessible = []
    error_info = None
    
    parsed = urllib.parse.urlparse(url, scheme="http")
    if not parsed.netloc:
        parsed = urllib.parse.urlparse("http://" + url)
    
    try:
        socket.gethostbyname(parsed.netloc.split(':')[0])
    except socket.gaierror:
        return {
            "accessible": [],
            "error": f"DNS resolution failed for '{parsed.netloc}' - check your internet connection"
        }
    except Exception as e:
        return {
            "accessible": [],
            "error": f"Cannot resolve hostname: {str(e)}"
        }
    
    for path in paths:
        try:
            full_url = f"{parsed.scheme}://{parsed.netloc}{path}" if path else f"{parsed.scheme}://{parsed.netloc}/"
            
            request = urllib.request.Request(
                full_url,
                method="HEAD",
                headers={"User-Agent": "AleEthicalTools/2.0"}
            )
            
            with urllib.request.urlopen(request, timeout=3) as response:
                if response.status < 400:
                    accessible.append((path, response.status))
        
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 303, 307, 308]:
                accessible.append((path, e.code))
        
        except (urllib.error.URLError, socket.timeout):
            pass
        except Exception:
            pass
    
    return {
        "accessible": accessible,
        "error": error_info
    }
