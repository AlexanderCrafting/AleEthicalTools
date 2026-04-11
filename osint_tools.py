

import urllib.request
import json
import re
import socket
import time
from urllib.error import URLError, HTTPError

ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"


def search_user_github(username):
    try:
        url = f"https://api.github.com/users/{username}"
        req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return {
                "found": True,
                "username": data.get("login"),
                "name": data.get("name"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "location": data.get("location"),
                "repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "url": data.get("html_url"),
            }
    except HTTPError as e:
        if e.code == 404:
            return {"found": False}
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def search_user_twitter(username):
    try:
        url = f"https://twitter.com/{username}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return {
                        "found": True,
                        "username": username,
                        "url": f"https://twitter.com/{username}",
                        "note": "Perfil encontrado en Twitter/X"
                    }
        except HTTPError as e:
            if e.code == 404:
                return {"found": False, "username": username}
            
        return {"found": False, "username": username}
    except Exception as e:
        return {"error": str(e)}


def search_user_instagram(username):
    try:
        url = f"https://www.instagram.com/{username}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return {
                        "found": True,
                        "username": username,
                        "url": f"https://www.instagram.com/{username}",
                        "note": "Perfil encontrado en Instagram"
                    }
        except HTTPError as e:
            if e.code == 404:
                return {"found": False, "username": username}
            
        return {"found": False, "username": username}
    except Exception as e:
        return {"error": str(e)}


def search_user_reddit(username):
    try:
        url = f"https://www.reddit.com/user/{username}/about.json"
        req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
        
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            user_data = data.get("data", {})
            
            return {
                "found": True,
                "username": user_data.get("name"),
                "karma": user_data.get("link_karma") + user_data.get("comment_karma"),
                "created": user_data.get("created"),
                "url": f"https://reddit.com/user/{username}",
                "verified": user_data.get("verified"),
            }
    except HTTPError as e:
        if e.code == 404:
            return {"found": False, "username": username}
        return {"found": False, "username": username}
    except Exception as e:
        return {"error": str(e)}


def search_email_compromised(email):
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        req = urllib.request.Request(url, headers={"User-Agent": "AleEthicalTools/2.0"})
        
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                breaches = [b.get("Name") for b in data]
                return {
                    "email": email,
                    "compromised": True,
                    "breaches": breaches,
                    "count": len(breaches)
                }
        except HTTPError as e:
            if e.code == 404:
                return {
                    "email": email,
                    "compromised": False,
                    "breaches": []
                }
            return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def search_username_available(platforms_list):
    results = {
        "available_on": [],
        "taken_on": [],
        "error": []
    }
    
    for platform in platforms_list:
        try:
            url = f"https://{platform}/{platforms_list[platform]}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            
            if urllib.request.urlopen(req, timeout=3):
                results["taken_on"].append(platform)
        except:
            results["available_on"].append(platform)
    
    return results


def search_user_linkedin(name):
    try:
        return {
            "found_url": f"https://www.linkedin.com/in/{name.lower().replace(' ', '-')}",
            "note": "URL potencial de LinkedIn - verificar manualmente"
        }
    except Exception as e:
        return {"error": str(e)}


def reverse_email_lookup(email):
    results = {
        "email": email,
        "found_on": []
    }
    
    services = {
        "GitHub": f"https://github.com/search?q={email}&type=users",
        "Keybase": f"https://keybase.io/search?q={email}",
    }
    
    for service, url in services.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    results["found_on"].append(service)
        except:
            pass
    
    return results


def check_domain_availability(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {
            "domain": domain,
            "available": True,
            "ip": ip,
            "status": "Registrado y resolvible"
        }
    except socket.gaierror:
        return {
            "domain": domain,
            "available": False,
            "status": "No resolvible (posiblemente disponible)"
        }
    except Exception as e:
        return {
            "domain": domain,
            "available": None,
            "error": str(e)
        }


def search_subdomain_enumeration(domain):
    subdomains = [
        "www", "mail", "ftp", "admin", "test", "staging",
        "api", "dev", "prod", "cdn", "static", "blog",
        "app", "mobile", "support", "help", "login",
        "dashboard", "panel", "backup", "server"
    ]
    
    found = []
    not_found = []
    
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            found.append((full_domain, ip))
        except:
            not_found.append(full_domain)
        
        time.sleep(0.1)  # Rate limiting
    
    return {
        "domain": domain,
        "found_subdomains": found,
        "count": len(found)
    }


def gather_osint_profile(username):
    profile = {
        "username": username,
        "sources": {}
    }
    
    print(f"{ANSI_CYAN}[*] Buscando en GitHub...{ANSI_RESET}")
    profile["sources"]["github"] = search_user_github(username)
    
    print(f"{ANSI_CYAN}[*] Buscando en Reddit...{ANSI_RESET}")
    profile["sources"]["reddit"] = search_user_reddit(username)
    
    print(f"{ANSI_CYAN}[*] Verificando Twitter...{ANSI_RESET}")
    profile["sources"]["twitter"] = search_user_twitter(username)
    
    print(f"{ANSI_CYAN}[*] Verificando Instagram...{ANSI_RESET}")
    profile["sources"]["instagram"] = search_user_instagram(username)
    
    print(f"{ANSI_CYAN}[*] Verificando LinkedIn...{ANSI_RESET}")
    profile["sources"]["linkedin"] = search_user_linkedin(username)
    
    return profile
