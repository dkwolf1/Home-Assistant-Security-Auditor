import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_DIR = Path(os.environ.get("APP_DIR", "/app"))
OPTIONS_PATH = Path(os.environ.get("OPTIONS_PATH", "/data/options.json"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/homeassistant/configuration.yaml"))
PORT = int(os.environ.get("PORT", "8099"))


def load_options():
    defaults = {
        "public_url": "",
        "scan_common_ports": False,
        "request_timeout_seconds": 6,
    }
    try:
        with OPTIONS_PATH.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except FileNotFoundError:
        loaded = {}
    except json.JSONDecodeError:
        loaded = {}
    return {**defaults, **loaded}


def normalize_target(value):
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"https://{value}"
    parsed = urllib.parse.urlparse(value)
    if not parsed.hostname:
        return None
    return parsed


def finding(check_id, title, severity, status, advice, details=None):
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "status": status,
        "advice": advice,
        "details": details or {},
    }


def severity_score(severity, status):
    if status == "pass":
        return 0
    return {
        "critical": 35,
        "high": 25,
        "medium": 14,
        "low": 7,
        "info": 0,
    }.get(severity, 0)


def dns_audit(parsed):
    host = parsed.hostname
    findings = []
    details = {"host": host}
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        details["addresses"] = addresses
        findings.append(finding(
            "dns.resolve",
            "DNS-resolutie werkt",
            "info",
            "pass",
            "DNS geeft IP-adressen terug. Controleer of dit de bedoelde proxy of tunnel is.",
            details,
        ))
        if "duckdns.org" in host.lower():
            findings.append(finding(
                "dns.duckdns",
                "DuckDNS hostnaam gedetecteerd",
                "info",
                "info",
                "Gebruik sterke Home Assistant authenticatie, HTTPS en een werkende ban/rate-limit configuratie.",
                {"provider": "DuckDNS"},
            ))
    except socket.gaierror as error:
        findings.append(finding(
            "dns.resolve",
            "DNS-resolutie mislukt",
            "high",
            "fail",
            "Controleer de hostnaam, DNS records en eventuele Cloudflare of DuckDNS configuratie.",
            {"error": str(error), **details},
        ))
    return findings


def tls_audit(parsed, timeout):
    if parsed.scheme != "https":
        return [finding(
            "tls.https",
            "Publieke URL gebruikt geen HTTPS",
            "high",
            "fail",
            "Gebruik HTTPS met een geldig certificaat voordat Home Assistant publiek bereikbaar is.",
            {"scheme": parsed.scheme},
        )]

    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                issuer = " / ".join("=".join(pair) for group in cert.get("issuer", []) for pair in group)
                expires_raw = cert.get("notAfter")
                expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expires - datetime.now(timezone.utc)).days
                status = "pass" if days_left >= 14 else "warn"
                severity = "low" if status == "warn" else "info"
                return [finding(
                    "tls.certificate",
                    "TLS-certificaat is geldig" if status == "pass" else "TLS-certificaat verloopt binnenkort",
                    severity,
                    status,
                    "Vernieuw certificaten ruim op tijd en controleer automatische renewal.",
                    {
                        "issuer": issuer,
                        "expires": expires.isoformat(),
                        "days_left": days_left,
                        "protocol": tls_socket.version(),
                    },
                )]
    except Exception as error:
        return [finding(
            "tls.certificate",
            "TLS-controle mislukt",
            "high",
            "fail",
            "Controleer certificaat, proxy forwarding en of poort 443 correct bereikbaar is.",
            {"error": str(error), "host": host, "port": port},
        )]


def http_audit(parsed, timeout):
    url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    request = urllib.request.Request(url, headers={"User-Agent": "HomeAssistantSecurityAuditor/0.1"})
    findings = []
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            server = headers.get("server", "")
            cf_ray = headers.get("cf-ray")
            findings.append(finding(
                "http.reachable",
                "Publieke endpoint reageert",
                "info",
                "pass",
                "Controleer of alleen de bedoelde Home Assistant interface publiek beschikbaar is.",
                {"status": response.status, "server": server},
            ))
            if "cloudflare" in server.lower() or cf_ray:
                findings.append(finding(
                    "proxy.cloudflare",
                    "Cloudflare signaal gedetecteerd",
                    "info",
                    "info",
                    "Controleer Cloudflare SSL mode, WAF regels, caching bypass voor Home Assistant en toegangsbeleid.",
                    {"server": server, "cf_ray": bool(cf_ray)},
                ))
            required_headers = {
                "strict-transport-security": ("HSTS ontbreekt", "medium", "Schakel HSTS in op de reverse proxy wanneer HTTPS stabiel werkt."),
                "x-frame-options": ("X-Frame-Options ontbreekt", "low", "Voeg framebescherming toe op de proxy om clickjacking risico te verlagen."),
                "referrer-policy": ("Referrer-Policy ontbreekt", "low", "Gebruik een referrer policy zoals same-origin of strict-origin-when-cross-origin."),
                "content-security-policy": ("Content-Security-Policy ontbreekt", "low", "Overweeg een CSP op de proxy, maar test goed met Home Assistant front-end resources."),
            }
            for header, (title, severity, advice) in required_headers.items():
                findings.append(finding(
                    f"header.{header}",
                    title if header not in headers else f"{header} aanwezig",
                    severity if header not in headers else "info",
                    "warn" if header not in headers else "pass",
                    advice,
                    {"header": header, "value": headers.get(header)},
                ))
    except urllib.error.HTTPError as error:
        findings.append(finding(
            "http.reachable",
            "Publieke endpoint geeft HTTP-fout",
            "medium",
            "warn",
            "Een HTTP-fout kan normaal zijn achter authenticatie, maar controleer of de proxy correct naar Home Assistant wijst.",
            {"status": error.code},
        ))
    except Exception as error:
        findings.append(finding(
            "http.reachable",
            "Publieke endpoint niet bereikbaar",
            "high",
            "fail",
            "Controleer DNS, firewall, poortforwarding, Cloudflare tunnel of reverse proxy configuratie.",
            {"error": str(error)},
        ))
    return findings


def port_audit(parsed, timeout):
    host = parsed.hostname
    checks = [(80, "HTTP"), (443, "HTTPS"), (8123, "Home Assistant default"), (4433, "Alternative HTTPS")]
    findings = []
    for port, label in checks:
        try:
            with socket.create_connection((host, port), timeout=min(timeout, 3)):
                status = "warn" if port in (80, 8123) else "info"
                severity = "medium" if port == 8123 else "low"
                findings.append(finding(
                    f"port.{port}",
                    f"Poort {port} lijkt open ({label})",
                    severity,
                    status,
                    "Sluit onnodige publieke poorten. Publiceer bij voorkeur alleen 443 of gebruik een tunnel/access policy.",
                    {"port": port, "label": label},
                ))
        except OSError:
            findings.append(finding(
                f"port.{port}",
                f"Poort {port} lijkt gesloten ({label})",
                "info",
                "pass",
                "Geen actie nodig wanneer dit verwacht is.",
                {"port": port, "label": label},
            ))
    return findings


def local_config_audit():
    findings = []
    if not CONFIG_PATH.exists():
        return [finding(
            "ha.config",
            "configuration.yaml niet gevonden",
            "info",
            "info",
            "Lokale configuratie kon niet worden gelezen. Netwerkchecks blijven beschikbaar.",
            {"path": str(CONFIG_PATH)},
        )]

    text = CONFIG_PATH.read_text(encoding="utf-8", errors="ignore")
    lower = text.lower()
    checks = [
        ("ha.ip_ban", "ip_ban_enabled lijkt niet ingeschakeld", "medium", "Zet `ip_ban_enabled: true` aan onder `http:` wanneer je direct publiek exposeert.", "ip_ban_enabled: true" in lower),
        ("ha.login_attempts", "login_attempts_threshold ontbreekt", "low", "Stel `login_attempts_threshold` in zodat herhaalde mislukte logins beperkt worden.", "login_attempts_threshold" in lower),
        ("ha.trusted_proxies", "trusted_proxies ontbreekt", "medium", "Gebruik `trusted_proxies` wanneer Home Assistant achter een reverse proxy staat.", "trusted_proxies" in lower),
        ("ha.use_x_forwarded_for", "use_x_forwarded_for ontbreekt", "medium", "Gebruik `use_x_forwarded_for: true` alleen samen met correcte `trusted_proxies`.", "use_x_forwarded_for: true" in lower),
    ]
    if "http:" not in lower:
        findings.append(finding(
            "ha.http",
            "Geen expliciete http-configuratie gevonden",
            "info",
            "info",
            "Dit kan prima zijn. Controleer proxy- en securityinstellingen als Home Assistant extern bereikbaar is.",
            {"path": str(CONFIG_PATH)},
        ))
    for check_id, title, severity, advice, passed in checks:
        findings.append(finding(
            check_id,
            title if not passed else title.replace(" ontbreekt", " aanwezig").replace(" lijkt niet ingeschakeld", " is ingeschakeld"),
            "info" if passed else severity,
            "pass" if passed else "warn",
            advice,
            {"path": str(CONFIG_PATH)},
        ))
    return findings


def run_audit():
    options = load_options()
    parsed = normalize_target(options.get("public_url"))
    timeout = int(options.get("request_timeout_seconds") or 6)
    findings = []

    if parsed is None:
        findings.append(finding(
            "target.missing",
            "Geen publieke URL ingesteld",
            "medium",
            "warn",
            "Vul `public_url` in bij de add-on opties om externe toegang te controleren.",
        ))
    else:
        findings.extend(dns_audit(parsed))
        findings.extend(tls_audit(parsed, timeout))
        findings.extend(http_audit(parsed, timeout))
        if options.get("scan_common_ports"):
            findings.extend(port_audit(parsed, timeout))

    findings.extend(local_config_audit())
    risk_points = sum(severity_score(item["severity"], item["status"]) for item in findings)
    score = max(0, 100 - risk_points)
    severity_counts = {}
    for item in findings:
        if item["status"] != "pass":
            severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": urllib.parse.urlunparse(parsed) if parsed else None,
        "score": score,
        "severity_counts": severity_counts,
        "findings": findings,
        "options": {
            "scan_common_ports": bool(options.get("scan_common_ports")),
            "request_timeout_seconds": timeout,
        },
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args), flush=True)

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/api/audit":
            self.send_json(run_audit())
            return
        if parsed_path.path == "/api/options":
            self.send_json(load_options())
            return

        file_path = APP_DIR / "static" / ("index.html" if parsed_path.path in ("/", "") else parsed_path.path.lstrip("/"))
        if not file_path.resolve().is_relative_to((APP_DIR / "static").resolve()) or not file_path.exists():
            self.send_error(404)
            return
        content_type = "text/html; charset=utf-8"
        if file_path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif file_path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Home Assistant Security Auditor listening on {PORT}", flush=True)
    server.serve_forever()
