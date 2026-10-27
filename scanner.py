import socket
import ssl
import dns.resolver
from datetime import datetime, timezone
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError
from urllib.parse import urlparse

PORTS = [21, 22, 80, 443, 3306, 8080]
PORT_TIMEOUT = 2
PORT_ATTEMPTS = 3

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def scan_ports(domain):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": "Unable to resolve domain"}

    open_ports = []
    for port in PORTS:
        successful_attempts = 0
        for _ in range(PORT_ATTEMPTS):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_TIMEOUT)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    successful_attempts += 1
            except OSError:
                pass
            finally:
                sock.close()

        if successful_attempts >= 2:
            open_ports.append(port)

    return {"ip": ip, "open_ports": open_ports}

def check_spf(domain):
    try:
        records = dns.resolver.resolve(domain, "TXT")
        for record in records:
            text = record.to_text().strip('"')
            if text.lower().startswith("v=spf1"):
                return {"enabled": True, "record": text}
        return {"enabled": False, "record": None}
    except Exception:
        return {"enabled": False, "record": None}

def check_dmarc(domain):
    try:
        records = dns.resolver.resolve("_dmarc." + domain, "TXT")
        for record in records:
            text = record.to_text().strip('"')
            if text.lower().startswith("v=dmarc1"):
                return {"enabled": True, "record": text}
        return {"enabled": False, "record": None}
    except Exception:
        return {"enabled": False, "record": None}

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_socket:
                certificate = secure_socket.getpeercert()

        expiry = certificate.get("notAfter")
        if not expiry:
            return {"valid": False, "expiry": None, "days_remaining": None, "issuer": "Unknown"}

        expiry_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        current_time = datetime.now(timezone.utc)
        days_remaining = (expiry_date - current_time).days
        
        issuer_dict = dict(x[0] for x in certificate.get("issuer", ()))
        issuer_name = issuer_dict.get("organizationName", "Unknown CA")

        return {
            "valid": days_remaining >= 0,
            "expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "issuer": issuer_name
        }
    except Exception:
        return {"valid": False, "expiry": None, "days_remaining": None, "issuer": "N/A"}

def check_https(domain):
    try:
        request = Request("https://" + domain, headers={"User-Agent": "WebsiteSecurityScanner/1.0"})
        response = urlopen(request, timeout=8)
        return response.status < 400
    except Exception:
        return False

def check_http_redirect(domain):
    class NoRedirectHandler(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        opener = build_opener(NoRedirectHandler)
        request = Request("http://" + domain, headers={"User-Agent": "WebsiteSecurityScanner/1.0"})
        try:
            response = opener.open(request, timeout=8)
            location = response.headers.get("Location")
            if location:
                return location.lower().startswith("https://")
            return False
        except HTTPError as error:
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get("Location")
                if location:
                    return location.lower().startswith("https://")
            return False
    except Exception:
        return False

def check_security_headers(domain):
    results = {}
    try:
        request = Request("https://" + domain, headers={"User-Agent": "WebsiteSecurityScanner/1.0"})
        response = urlopen(request, timeout=8)
        for header in SECURITY_HEADERS:
            value = response.headers.get(header)
            results[header] = {"present": value is not None, "value": value}
    except Exception:
        for header in SECURITY_HEADERS:
            results[header] = {"present": False, "value": None}
    return results

def calculate_port_score(open_ports):
    score_table = {0: 20, 1: 17, 2: 14, 3: 11, 4: 7, 5: 3, 6: 0}
    return score_table.get(len(open_ports), 0)

def calculate_dns_score(spf, dmarc):
    score = 0
    if spf["enabled"]: score += 10
    if dmarc["enabled"]: score += 10
    return score

def scan_domain(domain):
    if "://" in domain:
        domain = urlparse(domain).hostname or ""
    domain = domain.strip().rstrip("/")

    port_result = scan_ports(domain)
    if "error" in port_result:
        return port_result

    spf_result = check_spf(domain)
    dmarc_result = check_dmarc(domain)
    ssl_result = check_ssl(domain)
    https_result = check_https(domain)
    redirect_result = check_http_redirect(domain)
    headers_result = check_security_headers(domain)

    port_score = calculate_port_score(port_result["open_ports"])
    dns_score = calculate_dns_score(spf_result, dmarc_result)

    # Header calculations (20 pts max)
    header_score = sum(4 for h in headers_result.values() if h["present"])

    # SSL calculations (20 pts max)
    ssl_score = 0
    if ssl_result["valid"]: ssl_score += 15
    if https_result: ssl_score += 5

    # Standardized 100-point total score
    ssl_tls_score = int((ssl_score / 20) * 30)       # Max 30
    sec_header_score = int((header_score / 20) * 30)  # Max 30
    
    total_score = ssl_tls_score + sec_header_score + port_score + dns_score

    if total_score >= 90: grade = "STRONG"
    elif total_score >= 75: grade = "GOOD"
    elif total_score >= 50: grade = "NEEDS IMPROVEMENT"
    else: grade = "CRITICAL"

    return {
        "domain": domain,
        "ip": port_result["ip"],
        "open_ports": port_result["open_ports"],
        "ssl": ssl_result,
        "https": https_result,
        "http_redirect": redirect_result,
        "headers": headers_result,
        "spf": spf_result,
        "dmarc": dmarc_result,
        "scores": {
            "ssl_tls": ssl_tls_score,
            "headers": sec_header_score,
            "ports": port_score,
            "dns": dns_score,
            "total": total_score,
            "grade": grade
        }
    }
