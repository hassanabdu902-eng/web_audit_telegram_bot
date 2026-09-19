"""
60-check web security audit engine with polite request pacing.

Safety:
- Default mode performs passive/low-impact checks.
- Active injection checks are only executed when active_allowed=True.
- Only enable active testing for targets you own or are explicitly authorized to test.
"""
import concurrent.futures
import json
import re
import socket
import ssl
import subprocess
import time
import os
import random
import threading
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

UA = "Authorized-Web-Audit-Bot/1.0"

SCAN_CATALOG = [
    "WordPress Users", "Admin / Control Panels / cPanel", "XML-RPC", "robots.txt", "WHOIS",
    "WAF Detection", "Port Scan", "SSL Certificate", "Security Headers", "DNS Lookup",
    "Subdomain Scan", "HTTP Methods Testing", "Technology Detection", "Cookie Security",
    "CORS Configuration", "Directory Listing Check", "Sensitive Files Check", "WordPress Plugins",
    "WordPress Version", "SQL Injection Test", "XSS Test", "File Inclusion Test",
    "Email Security Records", "API Endpoints", "Source Code Analysis", "Contact Information Harvested",
    "Login Security", "CT Logs", "Wayback", "WordPress CVE Vulnerability Check",
    "Phishing & Scam Detection", "Scam Advisor & Trust Analysis", "CRLF Injection", "Open Redirect",
    "Clickjacking Protection", "VCS Exposure", "Command Injection", "Security.txt", "Backup Files",
    "Server Information Disclosure", "Sensitive Data", "Subdomain Takeover", "HSTS Quality",
    "CSP Quality", "TLS Protocols", "TLS Certificate Chain", "TLS Cipher Review", "DNSSEC",
    "CAA Record", "MX Records", "SPF Quality", "DMARC Quality", "Sitemap Exposure",
    "HTTP Redirect Security", "Mixed Content", "External Resource Integrity", "Security.txt Quality",
    "Cache-Control Security", "Information Disclosure Headers", "API Documentation Exposure"
]

TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.35"))
REQUEST_JITTER = float(os.getenv("REQUEST_JITTER", "0.15"))
REQUEST_RETRIES = int(os.getenv("REQUEST_RETRIES", "2"))
REQUEST_BACKOFF = float(os.getenv("REQUEST_BACKOFF", "1.5"))

S = requests.Session()
S.headers.update({"User-Agent": UA})
requests.packages.urllib3.disable_warnings()

_request_lock = threading.Lock()
_last_request_at = 0.0

def _polite_wait():
    global _last_request_at
    with _request_lock:
        now = time.monotonic()
        target = _last_request_at + max(0.0, REQUEST_DELAY)
        if now < target:
            time.sleep(target - now)
        jitter = random.uniform(0.0, max(0.0, REQUEST_JITTER))
        if jitter:
            time.sleep(jitter)
        _last_request_at = time.monotonic()

def request(method, url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("allow_redirects", True)
    last_exc = None
    for attempt in range(max(0, REQUEST_RETRIES) + 1):
        _polite_wait()
        try:
            resp = S.request(method, url, **kwargs)
            if resp.status_code in (429, 502, 503, 504) and attempt < REQUEST_RETRIES:
                time.sleep(REQUEST_BACKOFF * (2 ** attempt))
                continue
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < REQUEST_RETRIES:
                time.sleep(REQUEST_BACKOFF * (2 ** attempt))
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("HTTP request failed")


def result(n, name, status="INFO", detail="", risk="INFO", evidence=""):
    return {"scan": n, "name": name, "status": status, "risk": risk,
            "detail": str(detail)[:4000], "evidence": str(evidence)[:4000]}

def get(url, **kwargs):
    return request("GET", url, **kwargs)

def head(url):
    try:
        return request("HEAD", url)
    except Exception:
        return request("GET", url, stream=True)

def host_of(url):
    return urlparse(url).hostname or ""

def root(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def dns_records(host):
    out = {}
    try:
        out["A"] = sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception as e:
        out["A"] = [f"error: {e}"]
    try:
        out["PTR"] = socket.gethostbyaddr(out["A"][0])[0] if out["A"] and "." in out["A"][0] else ""
    except Exception:
        out["PTR"] = ""
    return out

def tls_info(host, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
            return {
                "protocol": ss.version(),
                "cipher": ss.cipher()[0] if ss.cipher() else "",
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notAfter": cert.get("notAfter"),
            }

def severity_for_missing_headers(h):
    required = {
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Referrer-Policy": "Referrer policy",
        "Permissions-Policy": "Permissions policy",
    }
    return [label for key, label in required.items() if key.lower() not in h]

def fetch_body(url):
    r = get(url)
    return r, r.text[:1000000]

def passive_active_check(url, active_allowed):
    # Returns only non-destructive authorization-gated tests.
    if not active_allowed:
        return "SKIPPED", "Disabled: Telegram user is not in AUTHORIZED_USERS."
    # Intentionally no exploit payloads are sent here.
    return "AUTHORIZED", "Authorized active-test slot. Add organization-approved test modules here."

def scan_url(url, active_allowed=False):
    started = datetime.now(timezone.utc).isoformat()
    p = urlparse(url)
    host = host_of(url)
    results = []

    # Fetch baseline once
    try:
        r, body = fetch_body(url)
        headers = {k.lower(): v for k, v in r.headers.items()}
        final_url = r.url
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", re.sub("<.*?>", "", m.group(1))).strip()
    except Exception as e:
        r = None; body = ""; headers = {}; final_url = url; title = ""
        baseline_error = str(e)

    # 0 WordPress users
    try:
        rr = get(urljoin(root(url), "/wp-json/wp/v2/users?per_page=1"))
        if rr.status_code == 200 and "application/json" in rr.headers.get("content-type",""):
            results.append(result(0, "WordPress Users", "REVIEW", "WordPress user API appears accessible.", "MEDIUM", rr.text[:500]))
        else:
            results.append(result(0, "WordPress Users", "PASS", "No public WordPress user API result detected.", "INFO"))
    except Exception as e:
        results.append(result(0, "WordPress Users", "INFO", e))

    # 1 admin/control panels (passive existence checks)
    admin_paths = [
        "/wp-admin/", "/wp-login.php", "/admin/", "/admin/login/", "/administrator/",
        "/login/", "/admincp/", "/cpanel/", "/cpanel/login/", "/controlpanel/",
        "/panel/", "/dashboard/", "/manage/", "/management/", "/backend/",
        "/backoffice/", "/console/", "/portal/admin/", "/whm/", "/webmail/",
        "/roundcube/", "/phpmyadmin/", "/pma/", "/server-status", "/server-info"
    ]
    found = []
    for path in admin_paths:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404, 410):
                found.append(f"{path} HTTP {rr.status_code} {rr.reason}")
        except Exception: pass

    # cPanel/WHM/Webmail service ports are checked separately so the report can
    # distinguish a web path from a panel service listening on its standard ports.
    cpanel_ports = {
        2082: "cPanel HTTP", 2083: "cPanel HTTPS",
        2086: "WHM HTTP", 2087: "WHM HTTPS",
        2095: "Webmail HTTP", 2096: "Webmail HTTPS",
    }
    cpanel_port_lines = []
    for pt, label in cpanel_ports.items():
        try:
            with socket.create_connection((host, pt), timeout=min(float(os.getenv("PORT_TIMEOUT", "1.5")), 2.0)):
                cpanel_port_lines.append(f"{pt}/tcp OPEN — {label}")
        except OSError:
            pass

    # Lightweight hostname discovery for common cPanel ecosystem names. DNS-only;
    # no credentials or authenticated panel actions are attempted.
    panel_hosts = []
    for prefix in ("cpanel", "whm", "webmail", "mail"):
        candidate = f"{prefix}.{host}"
        try:
            ips = sorted(set(socket.gethostbyname_ex(candidate)[2]))
            if ips:
                panel_hosts.append(f"{candidate} → {', '.join(ips)}")
        except OSError:
            pass

    evidence = []
    if found:
        evidence.append("HTTP endpoint discovery:")
        evidence.extend(found)
    if cpanel_port_lines:
        evidence.append("cPanel service ports:")
        evidence.extend(cpanel_port_lines)
    if panel_hosts:
        evidence.append("Common panel hostnames:")
        evidence.extend(panel_hosts)
    if not evidence:
        evidence.append("No common management endpoints, cPanel service ports, or common panel hostnames detected.")

    results.append(result(1, "Admin / Control Panels / cPanel", "REVIEW" if (found or cpanel_port_lines or panel_hosts) else "PASS",
                          f"Management discovery: HTTP endpoints={len(found)}, cPanel ports={len(cpanel_port_lines)}, panel hostnames={len(panel_hosts)}.",
                          "MEDIUM" if (found or cpanel_port_lines or panel_hosts) else "INFO", "\n".join(evidence)))

    # 2 XML-RPC
    try:
        rr = head(urljoin(root(url), "/xmlrpc.php"))
        results.append(result(2, "XML-RPC", "REVIEW" if rr.status_code == 200 else "PASS",
                              f"/xmlrpc.php returned HTTP {rr.status_code}.",
                              "LOW" if rr.status_code == 200 else "INFO"))
    except Exception as e: results.append(result(2,"XML-RPC","INFO",e))

    # 3 robots
    try:
        rr = get(urljoin(root(url), "/robots.txt"))
        results.append(result(3, "robots.txt", "PASS" if rr.status_code == 200 else "INFO",
                              f"HTTP {rr.status_code}. Content length {len(rr.text)}.",
                              "INFO", rr.text[:2000]))
    except Exception as e: results.append(result(3,"robots.txt","INFO",e))

    # 4 WHOIS (no external whois dependency; DNS identity only)
    results.append(result(4, "WHOIS", "INFO", "WHOIS is provider-dependent; this build records domain/DNS identity without scraping a third-party WHOIS site.", "INFO", host))

    # 5 WAF heuristic
    waf_markers = ["cloudflare","akamai","imperva","sucuri","incapsula","aws"]
    server = (r.headers.get("Server","") if r else "").lower()
    via = (r.headers.get("Via","") if r else "").lower()
    marker = next((x for x in waf_markers if x in server + " " + via), None)
    results.append(result(5, "WAF Detection", "DETECTED" if marker else "INFO",
                          f"Heuristic marker: {marker or 'none observed'}; this is not proof of absence/presence.",
                          "INFO"))

    # 6 local TCP port scan. No external scanning API is used.
    # The connections originate from the machine running this bot.
    port_env = os.getenv(
        "PORTS",
        "20,21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,"
        "1433,1521,2049,2375,3000,3306,3389,5000,5432,5601,5900,6379,6443,"
        "8000,8001,8008,8080,8081,8088,8089,8090,8443,8444,8880,8888,9000,9001,9090,9200,9300,"
        "10000,11211,15672,18080,20000,2082,2083,2086,2087,2095,2096,2375,2376,27017,50000"
    )
    try:
        ports = sorted({int(x.strip()) for x in port_env.split(",") if x.strip()})
        ports = [p for p in ports if 1 <= p <= 65535][:200]
    except ValueError:
        ports = [22, 80, 443, 8080, 8443]

    port_timeout = float(os.getenv("PORT_TIMEOUT", "1.5"))
    port_workers = min(int(os.getenv("PORT_WORKERS", "20")), 40)

    def tcp_probe(pt):
        started = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(port_timeout)
        try:
            rc = sock.connect_ex((host, pt))
            elapsed = round((time.monotonic() - started) * 1000)
            if rc == 0:
                return pt, "OPEN", elapsed
            if rc in (111, 61, 10061):
                return pt, "CLOSED", elapsed
            return pt, "FILTERED/UNKNOWN", elapsed
        except socket.timeout:
            return pt, "FILTERED/UNKNOWN", round((time.monotonic() - started) * 1000)
        except OSError as e:
            return pt, f"ERROR({getattr(e, 'errno', 'n/a')})", round((time.monotonic() - started) * 1000)
        finally:
            sock.close()

    port_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=port_workers) as ex:
        futures = [ex.submit(tcp_probe, pt) for pt in ports]
        for future in concurrent.futures.as_completed(futures):
            port_results.append(future.result())

    port_results.sort()
    open_ports = [x for x in port_results if x[1] == "OPEN"]
    closed_ports = [x for x in port_results if x[1] == "CLOSED"]
    filtered_ports = [x for x in port_results if x[1] == "FILTERED/UNKNOWN"]

    service_names = {
        20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
        587: "SMTP submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        2049: "NFS", 2375: "Docker API", 2376: "Docker TLS", 3000: "App/Dev", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis",
        6443: "Kubernetes API", 8000: "HTTP-alt", 8080: "HTTP proxy/alt", 8443: "HTTPS-alt",
        9200: "Elasticsearch", 10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ",
        2082: "cPanel HTTP", 2083: "cPanel HTTPS", 2086: "WHM HTTP", 2087: "WHM HTTPS",
        2095: "Webmail HTTP", 2096: "Webmail HTTPS", 27017: "MongoDB",
    }
    port_lines = [f"{pt}/tcp {state} ({ms} ms) — {service_names.get(pt, 'Unknown/common service')}" for pt, state, ms in port_results]
    results.append(result(
        6, "Port Scan", "INFO",
        f"Scanned {len(port_results)} TCP ports from the bot server with service-name hints. "
        f"Open={len(open_ports)}, Closed={len(closed_ports)}, Filtered/Unknown={len(filtered_ports)}. "
        f"cPanel/WHM/Webmail standard ports are included.",
        "INFO", "\\n".join(port_lines)
    ))

    # 7 TLS
    try:
        ti = tls_info(host, 443)
        results.append(result(7, "SSL Certificate", "PASS", f"TLS {ti['protocol']}, cipher {ti['cipher']}, expires {ti['notAfter']}.", "INFO", json.dumps(ti, default=str)))
    except Exception as e:
        results.append(result(7, "SSL Certificate", "WARN", e, "MEDIUM"))

    # 8 headers
    if r:
        missing = severity_for_missing_headers(headers)
        results.append(result(8, "Security Headers", "WARN" if missing else "PASS",
                              f"Missing/review: {', '.join(missing) if missing else 'none'}",
                              "MEDIUM" if missing else "INFO", json.dumps(dict(r.headers))))
    else:
        results.append(result(8, "Security Headers", "ERROR", baseline_error, "HIGH"))

    # 9 DNS
    dns = dns_records(host)
    results.append(result(9, "DNS Lookup", "PASS" if dns.get("A") else "WARN", json.dumps(dns), "INFO"))

    # 10 subdomains: CT logs would need an API; use common-name DNS probes conservatively
    common_subs = ["www","mail","api","dev","staging","test","admin","cpanel","whm","webmail","portal","vpn","git","status"]
    found_subs = []
    for sub in common_subs:
        name = f"{sub}.{host}"
        try:
            ip = socket.gethostbyname(name)
            found_subs.append(f"{name} -> {ip}")
        except Exception: pass
    results.append(result(10, "Subdomain Scan", "INFO", f"Resolvable common subdomains: {len(found_subs)}", "INFO", "\n".join(found_subs) or "No tested common subdomains resolved."))

    # 11 HTTP method matrix. GET/HEAD are observed directly; potentially state-changing
    # methods are not blindly sent. OPTIONS is used to record the server's Allow header.
    try:
        method_rows = []
        for method in ("GET", "HEAD"):
            try:
                mr = request(method, url, allow_redirects=False)
                method_rows.append(f"{method} HTTP {mr.status_code} {mr.reason}")
            except Exception as me:
                method_rows.append(f"{method} ERROR {me}")
        rr = request("OPTIONS", url, allow_redirects=False)
        allow = rr.headers.get("Allow", "")
        method_rows.append(f"OPTIONS HTTP {rr.status_code} {rr.reason}")
        if allow:
            method_rows.append(f"Allow: {allow}")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            method_rows.append(f"{method} NOT ACTIVELY PROBED (state-changing method)")
        results.append(result(11, "HTTP Methods Testing", "INFO",
                              "Observed safe methods plus server-advertised methods. State-changing methods are intentionally not blindly executed.",
                              "INFO", "\n".join(method_rows)))
    except Exception as e: results.append(result(11,"HTTP Methods Testing","INFO",e))

    # 12 technology
    tech = []
    txt = ((r.headers.get("Server","") if r else "") + " " + body[:10000]).lower()
    for needle, label in [("apache","Apache"),("nginx","Nginx"),("cloudflare","Cloudflare"),("laravel","Laravel"),("wordpress","WordPress"),("jquery","jQuery"),("bootstrap","Bootstrap"),("angular","Angular"),("react","React")]:
        if needle in txt: tech.append(label)
    tech_unique = sorted(set(tech))
    tech_evidence = [f"Server: {r.headers.get('Server','not disclosed') if r else 'not available'}"]
    tech_evidence.append(f"X-Powered-By: {r.headers.get('X-Powered-By','not disclosed') if r else 'not available'}")
    tech_evidence.append(f"HTML/title indicators: {title or 'none'}")
    results.append(result(12, "Technology Detection", "INFO",
                          f"Observed technology indicators: {tech_unique or 'none'}", "INFO", "\n".join(tech_evidence)))

    # 13 cookies
    cookies = []
    if r:
        for c in r.cookies:
            # requests cookie flags are not fully exposed; inspect Set-Cookie header instead.
            pass
        set_cookie = r.headers.get("Set-Cookie","")
        cookies = [x.strip() for x in set_cookie.split(",") if "=" in x] if set_cookie else []
    weak = []
    if r and "set-cookie" in headers:
        raw = headers["set-cookie"].lower()
        if "secure" not in raw: weak.append("Secure")
        if "httponly" not in raw: weak.append("HttpOnly")
        if "samesite" not in raw: weak.append("SameSite")
    results.append(result(13, "Cookie Security", "WARN" if weak else "PASS", f"Cookie flags needing review: {weak or 'none observed'}", "LOW" if weak else "INFO"))

    # 14 CORS
    acao = r.headers.get("Access-Control-Allow-Origin") if r else None
    acac = r.headers.get("Access-Control-Allow-Credentials") if r else None
    acam = r.headers.get("Access-Control-Allow-Methods") if r else None
    cors_issue = bool(acao == "*" and str(acac).lower() == "true")
    results.append(result(14, "CORS Configuration", "WARN" if cors_issue else "INFO",
                          f"Origin={acao or 'not present'}; Credentials={acac or 'not present'}; Methods={acam or 'not present'}",
                          "MEDIUM" if cors_issue else "INFO",
                          f"Access-Control-Allow-Origin: {acao or 'not present'}\nAccess-Control-Allow-Credentials: {acac or 'not present'}\nAccess-Control-Allow-Methods: {acam or 'not present'}"))

    # 15 directory listing heuristic
    listing = bool(re.search(r"<title>\s*Index of /", body, re.I)) if body else False
    results.append(result(15, "Directory Listing Check", "WARN" if listing else "PASS", "Index of page detected." if listing else "No directory-index signature detected.", "MEDIUM" if listing else "INFO"))

    # 16 sensitive files (existence checks only)
    sensitive_paths = [
        "/.env", "/.env.local", "/.env.production", "/.git/HEAD", "/.svn/entries",
        "/.DS_Store", "/config.php", "/config.php.bak", "/wp-config.php.bak",
        "/phpinfo.php", "/server-status", "/server-info", "/composer.json", "/package.json"
    ]
    exposed = []
    for path in sensitive_paths:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404, 410):
                exposed.append(f"{path} HTTP {rr.status_code} {rr.reason}")
        except Exception: pass
    results.append(result(16, "Sensitive Files Check", "WARN" if exposed else "PASS",
                          f"Sensitive/configuration paths returning a non-404 response: {len(exposed)}",
                          "HIGH" if exposed else "INFO", "\n".join(exposed) or "No tested sensitive paths returned a non-404/410 response."))

    # 17 plugins
    plugin_hits = re.findall(r"/wp-content/plugins/([^/\"']+)", body, re.I)
    results.append(result(17, "WordPress Plugins", "INFO", f"Observed plugin paths: {sorted(set(plugin_hits))[:30] or 'none'}", "INFO"))

    # 18 WP version
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([^"\']*)', body, re.I)
    results.append(result(18, "WordPress Version", "INFO", f"Detected: {m.group(1).strip() if m else 'not detected'}", "INFO"))

    # 19 SQL injection (authorization gated, no exploit payloads in this template)
    st, detail = passive_active_check(url, active_allowed)
    results.append(result(19, "SQL Injection Test", st, detail, "INFO"))

    # 20 XSS
    results.append(result(20, "XSS Test", st, detail, "INFO"))

    # 21 LFI/RFI
    results.append(result(21, "File Inclusion Test", st, detail, "INFO"))

    # 22 SPF/DMARC DNS TXT via dnspython optional
    try:
        import dns.resolver
        txts = [str(x) for x in dns.resolver.resolve(host, "TXT")]
        spf = [x for x in txts if "v=spf1" in x.lower()]
        dmarc = [str(x) for x in dns.resolver.resolve("_dmarc."+host, "TXT") if "v=dmarc1" in str(x).lower()]
        results.append(result(22, "Email Security Records", "PASS" if spf and dmarc else "WARN",
                              f"SPF={'yes' if spf else 'no'}, DMARC={'yes' if dmarc else 'no'}",
                              "LOW" if not (spf and dmarc) else "INFO"))
    except Exception as e:
        results.append(result(22, "Email Security Records", "INFO", f"DNS TXT check unavailable: {e}", "INFO"))

    # 23 API endpoints
    api_paths = ["/api","/api/","/api/v1","/api/v2","/graphql","/graphiql","/rest","/swagger","/swagger-ui/","/swagger.json","/openapi.json","/openapi.yaml","/api-docs","/redoc"]
    api_found = []
    for path in api_paths:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404,410):
                api_found.append(f"{path}:{rr.status_code}")
        except Exception: pass
    results.append(result(23, "API Endpoints", "INFO", f"Potential endpoints: {api_found or 'none'}", "INFO"))

    # 24 source comments
    comments = re.findall(r"<!--(.*?)-->", body, re.S)[:10]
    secret_words = [c.strip() for c in comments if re.search(r"password|secret|token|api[_ -]?key", c, re.I)]
    results.append(result(24, "Source Code Analysis", "WARN" if secret_words else "PASS",
                          f"Suspicious comments: {len(secret_words)}", "HIGH" if secret_words else "INFO", "\n".join(secret_words)[:2000]))

    # 25 contact harvest
    emails = sorted(set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", body, re.I)))
    results.append(result(25, "Contact Information Harvested", "INFO", f"Emails found: {len(emails)}", "INFO", ", ".join(emails[:30])))

    # 26 login security
    login = []
    for path in ["/login","/signin","/wp-login.php","/admin/login"]:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404,410): login.append(f"{path}:{rr.status_code}")
        except Exception: pass
    results.append(result(26, "Login Security", "INFO", f"Login pages: {login or 'none detected'}", "INFO"))

    # 27 CT logs
    results.append(result(27, "CT Logs", "INFO", "Certificate Transparency lookup requires an external CT provider/API; not scraped by default.", "INFO"))

    # 28 Wayback
    try:
        rr = get("https://web.archive.org/cdx/search/cdx", params={"url":host+"/*","output":"json","filter":"statuscode:200","limit":"5"})
        results.append(result(28, "Wayback", "INFO", f"HTTP {rr.status_code}; archive query completed.", "INFO"))
    except Exception as e: results.append(result(28,"Wayback","INFO",e))

    # 29 WP CVE
    results.append(result(29, "WordPress CVE Vulnerability Check", "INFO", "Version/plugin-specific CVE matching is not performed without a vulnerability database integration.", "INFO"))

    # 30 phishing/scam
    https = final_url.lower().startswith("https://")
    results.append(result(30, "Phishing & Scam Detection", "INFO", f"Basic signals only: HTTPS={'yes' if https else 'no'}, title={title[:100]}", "INFO"))

    # 31 trust analysis
    results.append(result(31, "Scam Advisor & Trust Analysis", "INFO", "No third-party trust score is asserted by this build; use independent reputation services for additional context.", "INFO"))

    # 32 CRLF
    results.append(result(32, "CRLF Injection", st, detail, "INFO"))

    # 33 open redirect
    results.append(result(33, "Open Redirect", "INFO", "No redirect payload is tested in passive mode.", "INFO"))

    # 34 clickjacking
    xfo = r.headers.get("X-Frame-Options") if r else None
    csp = r.headers.get("Content-Security-Policy","") if r else ""
    frame_ok = bool(xfo or re.search(r"frame-ancestors", csp, re.I))
    results.append(result(34, "Clickjacking Protection", "PASS" if frame_ok else "WARN",
                          f"X-Frame-Options={xfo or 'missing'}; CSP frame-ancestors={'present' if re.search(r'frame-ancestors',csp,re.I) else 'missing'}",
                          "MEDIUM" if not frame_ok else "INFO"))

    # 35 VCS
    vcs = []
    for path in ["/.git/HEAD","/.svn/entries","/.hg/branch"]:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code == 200: vcs.append(path)
        except Exception: pass
    results.append(result(35, "VCS Exposure", "WARN" if vcs else "PASS", f"Detected: {vcs or 'none'}", "HIGH" if vcs else "INFO"))

    # 36 command injection
    results.append(result(36, "Command Injection", st, detail, "INFO"))

    # 37 security.txt
    try:
        rr = get(urljoin(root(url), "/.well-known/security.txt"))
        results.append(result(37, "Security.txt", "PASS" if rr.status_code == 200 else "WARN",
                              f"HTTP {rr.status_code}", "INFO" if rr.status_code == 200 else "LOW", rr.text[:2000]))
    except Exception as e: results.append(result(37,"Security.txt","INFO",e))

    # 38 backups / sensitive files: existence checks only; do not download content.
    backups = []
    for path in [
        "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.tgz", "/backup.7z",
        "/backup.rar", "/backup.sql", "/backup.sql.gz", "/backup.dump",
        "/site.zip", "/site.tar.gz", "/site.tar", "/site.tgz", "/site.7z",
        "/db.sql", "/db.sql.gz", "/database.sql", "/database.sql.gz",
        "/dump.sql", "/dump.sql.gz", "/database.dump",
        "/.backup", "/.backup.zip", "/.backup.tar.gz", "/.backups",
        "/backup/", "/backups/", "/old/", "/old-site/", "/archive/", "/archives/",
        "/www.zip", "/public_html.zip", "/htdocs.zip", "/web.zip",
        "/source.zip", "/source.tar.gz", "/src.zip", "/release.zip",
        "/deploy.zip", "/dist.zip", "/build.zip",
        "/config.php.bak", "/wp-config.php.bak", "/.env.bak", "/.env.old",
        "/.env.save", "/.env~", "/.git/HEAD", "/.svn/entries",
        "/composer.json.bak", "/package.json.bak"
    ]:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404, 410): backups.append(f"{path} HTTP {rr.status_code} {rr.reason}")
        except Exception: pass
    results.append(result(38, "Backup Files", "WARN" if backups else "PASS", f"Potential backup/sensitive paths responding: {len(backups)}", "HIGH" if backups else "INFO", "\n".join(backups) or "No tested backup/sensitive paths returned a non-404/410 response."))

    # 39 server disclosure
    sv = r.headers.get("Server") if r else None
    results.append(result(39, "Server Information Disclosure", "WARN" if sv and re.search(r"/\d",sv) else "INFO",
                          f"Server header: {sv or 'not supplied'}", "LOW" if sv and re.search(r"/\d",sv) else "INFO"))

    # 40 sensitive data
    patterns = [r"AKIA[0-9A-Z]{16}", r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----", r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}"]
    hits = []
    for pat in patterns:
        if re.search(pat, body):
            hits.append(pat)
    results.append(result(40, "Sensitive Data", "WARN" if hits else "PASS", f"High-confidence secret patterns found: {len(hits)}", "HIGH" if hits else "INFO"))

    # 41 takeover signatures
    takeover_words = ["there is no app", "no such app", "heroku | no such app", "github pages", "repository not found"]
    takeover = any(x in body.lower() for x in takeover_words)
    results.append(result(41, "Subdomain Takeover", "WARN" if takeover else "INFO",
                          "Possible provider error signature observed." if takeover else "No common takeover signature observed.",
                          "HIGH" if takeover else "INFO"))

    # 42 HSTS quality
    sts = r.headers.get("Strict-Transport-Security", "") if r else ""
    hsts_max = re.search(r"max-age\s*=\s*(\d+)", sts, re.I)
    hsts_issues = []
    if final_url.lower().startswith("https://"):
        if not sts: hsts_issues.append("missing")
        elif not hsts_max: hsts_issues.append("missing max-age")
        elif int(hsts_max.group(1)) < 15552000: hsts_issues.append("short max-age")
        if sts and "includesubdomains" not in sts.lower(): hsts_issues.append("no includeSubDomains")
    results.append(result(42, "HSTS Quality", "WARN" if hsts_issues else "PASS",
                          f"Strict-Transport-Security: {sts or 'missing'}; review: {hsts_issues or 'none'}",
                          "MEDIUM" if hsts_issues else "INFO"))

    # 43 CSP quality
    csp_value = r.headers.get("Content-Security-Policy", "") if r else ""
    csp_issues = []
    if not csp_value:
        csp_issues.append("missing")
    else:
        low = csp_value.lower()
        if "default-src" not in low: csp_issues.append("no default-src")
        if "'unsafe-inline'" in low: csp_issues.append("unsafe-inline")
        if "'unsafe-eval'" in low: csp_issues.append("unsafe-eval")
        if re.search(r"(?:^|[\s;])(?:script-src|default-src)[^;]*\*", low):
            csp_issues.append("wildcard source")
    results.append(result(43, "CSP Quality", "WARN" if csp_issues else "PASS",
                          f"Review: {csp_issues or 'none'}", "MEDIUM" if csp_issues else "INFO",
                          csp_value[:3000]))

    # 44 TLS protocol support
    tls_protocols = {}
    for label, version in [
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]:
        if version is None:
            tls_protocols[label] = "unsupported-by-runtime"
            continue
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, 443), timeout=min(TIMEOUT, 6)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    tls_protocols[label] = "supported"
        except Exception:
            tls_protocols[label] = "not-negotiated"
    legacy = [x for x in ("TLSv1.0", "TLSv1.1") if tls_protocols.get(x) == "supported"]
    results.append(result(44, "TLS Protocols", "WARN" if legacy else "PASS",
                          json.dumps(tls_protocols), "HIGH" if legacy else "INFO"))

    # 45 TLS certificate validation
    cert_status, cert_detail = "PASS", ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cert_detail = json.dumps({
                    "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter"),
                    "verified": True,
                }, default=str)
    except Exception as e:
        cert_status, cert_detail = "WARN", f"Certificate validation/chain check failed: {e}"
    results.append(result(45, "TLS Certificate Chain", cert_status, cert_detail,
                          "HIGH" if cert_status == "WARN" else "INFO"))

    # 46 negotiated TLS cipher review
    cipher = ""
    try: cipher = tls_info(host, 443).get("cipher", "")
    except Exception: pass
    weak_cipher = bool(re.search(r"(RC4|3DES|DES|NULL|EXPORT|MD5|anon)", cipher, re.I))
    results.append(result(46, "TLS Cipher Review", "WARN" if weak_cipher else "PASS",
                          f"Negotiated cipher: {cipher or 'unknown'}",
                          "HIGH" if weak_cipher else "INFO"))

    # 47 DNSSEC
    try:
        import dns.resolver
        dns.resolver.resolve(host, "DNSKEY")
        results.append(result(47, "DNSSEC", "PASS", "DNSKEY records were returned.", "INFO"))
    except Exception as e:
        results.append(result(47, "DNSSEC", "INFO", f"DNSSEC could not be confirmed: {e}", "INFO"))

    # 48 CAA
    try:
        import dns.resolver
        caa = [str(x) for x in dns.resolver.resolve(host, "CAA")]
        results.append(result(48, "CAA Record", "PASS" if caa else "INFO",
                              f"CAA records: {caa or 'none observed'}", "INFO"))
    except Exception as e:
        results.append(result(48, "CAA Record", "INFO", f"No CAA record confirmed: {e}", "INFO"))

    # 49 MX
    try:
        import dns.resolver
        mx = sorted(str(x.exchange).rstrip(".") for x in dns.resolver.resolve(host, "MX"))
        results.append(result(49, "MX Records", "PASS" if mx else "INFO",
                              f"Mail exchangers: {mx or 'none observed'}", "INFO"))
    except Exception as e:
        results.append(result(49, "MX Records", "INFO", f"MX lookup unavailable: {e}", "INFO"))

    # 50 SPF quality
    try:
        import dns.resolver
        txts = [str(x).replace('"', '') for x in dns.resolver.resolve(host, "TXT")]
        spfs = [x for x in txts if "v=spf1" in x.lower()]
        issues = []
        if not spfs: issues.append("missing")
        elif len(spfs) > 1: issues.append("multiple SPF records")
        elif "+all" in spfs[0].lower(): issues.append("+all")
        results.append(result(50, "SPF Quality", "WARN" if issues else "PASS",
                              f"SPF records: {spfs or 'none'}; review: {issues or 'none'}",
                              "MEDIUM" if issues else "INFO"))
    except Exception as e:
        results.append(result(50, "SPF Quality", "INFO", e, "INFO"))

    # 51 DMARC quality
    try:
        import dns.resolver
        dmarcs = [str(x).replace('"', '') for x in dns.resolver.resolve("_dmarc." + host, "TXT")]
        issues = []
        if not dmarcs: issues.append("missing")
        elif re.search(r"(?:^|;)\s*p=none(?:;|$)", dmarcs[0], re.I): issues.append("policy=none")
        results.append(result(51, "DMARC Quality", "WARN" if issues else "PASS",
                              f"DMARC: {dmarcs or 'none'}; review: {issues or 'none'}",
                              "LOW" if issues else "INFO"))
    except Exception as e:
        results.append(result(51, "DMARC Quality", "INFO", e, "INFO"))

    # 52 sitemap
    try:
        rr = get(urljoin(root(url), "/sitemap.xml"))
        urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", rr.text, re.I | re.S)[:100]
        results.append(result(52, "Sitemap Exposure", "INFO" if rr.status_code == 200 else "PASS",
                              f"HTTP {rr.status_code}; URLs listed: {len(urls)}", "INFO",
                              "\n".join(urls[:50])))
    except Exception as e:
        results.append(result(52, "Sitemap Exposure", "INFO", e, "INFO"))

    # 53 redirect security
    try:
        rr = get(url, allow_redirects=True)
        history = [h.url for h in rr.history] + [rr.url]
        issues = []
        if any(urlparse(u).scheme.lower() == "http" for u in history): issues.append("redirect chain contains HTTP")
        if any((urlparse(u).hostname or "").lower() != host.lower() for u in history): issues.append("redirect chain changes host")
        results.append(result(53, "HTTP Redirect Security", "WARN" if issues else "PASS",
                              f"Redirects: {len(rr.history)}; review: {issues or 'none'}",
                              "MEDIUM" if issues else "INFO", "\n".join(history)))
    except Exception as e:
        results.append(result(53, "HTTP Redirect Security", "INFO", e, "INFO"))

    # 54 mixed content
    mixed = []
    if final_url.lower().startswith("https://"):
        for m in re.finditer(r'(?:src|href|action)\s*=\s*["\'](http://[^"\']+)', body, re.I):
            mixed.append(m.group(1))
    results.append(result(54, "Mixed Content", "WARN" if mixed else "PASS",
                          f"HTTP resources/forms found in HTTPS page: {len(mixed)}",
                          "MEDIUM" if mixed else "INFO", "\n".join(mixed[:50])))

    # 55 external resource integrity
    sri_missing = []
    if body:
        for tag in re.findall(r"<(?:script|link)\b[^>]*>", body, re.I):
            src = re.search(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', tag, re.I)
            if not src: continue
            resource = urljoin(final_url, src.group(1))
            if urlparse(resource).netloc and urlparse(resource).netloc.lower() != host.lower():
                if "integrity=" not in tag.lower(): sri_missing.append(resource)
    results.append(result(55, "External Resource Integrity", "WARN" if sri_missing else "PASS",
                          f"Cross-origin script/link resources without SRI: {len(sri_missing)}",
                          "LOW" if sri_missing else "INFO", "\n".join(sri_missing[:50])))

    # 56 security.txt quality
    try:
        rr = get(urljoin(root(url), "/.well-known/security.txt"))
        txt = rr.text if rr.status_code == 200 else ""
        fields = {m.group(1).lower() for m in re.finditer(r"^([A-Za-z-]+):", txt, re.M)}
        issues = []
        if rr.status_code != 200: issues.append("missing")
        else:
            if "contact" not in fields: issues.append("missing Contact")
            if "expires" not in fields: issues.append("missing Expires")
        results.append(result(56, "Security.txt Quality", "WARN" if issues else "PASS",
                              f"Review: {issues or 'none'}", "LOW" if issues else "INFO", txt[:3000]))
    except Exception as e:
        results.append(result(56, "Security.txt Quality", "INFO", e, "INFO"))

    # 57 cache-control
    cache = r.headers.get("Cache-Control", "") if r else ""
    set_cookie = r.headers.get("Set-Cookie", "") if r else ""
    issues = []
    if set_cookie and cache and "no-store" not in cache.lower() and "private" not in cache.lower():
        issues.append("cookie-bearing response is not marked private/no-store")
    results.append(result(57, "Cache-Control Security", "WARN" if issues else "PASS",
                          f"Cache-Control: {cache or 'missing'}; review: {issues or 'none'}",
                          "MEDIUM" if issues else "INFO"))

    # 58 information disclosure headers
    disclosure = []
    for key in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        val = r.headers.get(key) if r else None
        if val: disclosure.append(f"{key}: {val}")
    results.append(result(58, "Information Disclosure Headers", "WARN" if disclosure else "PASS",
                          f"Technology/version disclosure headers: {len(disclosure)}",
                          "LOW" if disclosure else "INFO", "\n".join(disclosure)))

    # 59 API documentation exposure
    docs = []
    for path in ["/swagger", "/swagger-ui/", "/swagger.json", "/openapi.json",
                 "/openapi.yaml", "/api-docs", "/redoc"]:
        try:
            rr = head(urljoin(root(url), path))
            if rr.status_code not in (404, 410): docs.append(f"{path}:{rr.status_code}")
        except Exception: pass
    results.append(result(59, "API Documentation Exposure", "REVIEW" if docs else "PASS",
                          f"Potential API documentation endpoints: {docs or 'none'}",
                          "LOW" if docs else "INFO"))

    # Ensure exactly 60
    results = sorted(results, key=lambda x: x["scan"])
    results = results[:60]

    counts = {"findings":0,"high":0,"medium":0,"low":0}
    for x in results:
        if x["status"] in ("WARN","REVIEW","ERROR"):
            counts["findings"] += 1
            k = x["risk"].lower()
            if k in counts: counts[k] += 1

    return {
        "target": url,
        "final_url": final_url,
        "started": started,
        "completed": datetime.now(timezone.utc).isoformat(),
        "title": title,
        "summary": counts,
        "results": results,
        "scan_catalog": [{"scan": i, "name": name} for i, name in enumerate(SCAN_CATALOG)],
    }
