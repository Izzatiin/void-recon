import argparse
import asyncio
import json
import logging
import re
import socket
import ssl
import sys
import urllib.request
from urllib.parse import urlparse
from typing import Dict, List, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

# Logging Setup
logging.basicConfig(
    filename="void_recon.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

console = Console()

def clean_target_input(raw_input: str) -> str:
    """Sanitizes user input automatically."""
    raw_input = raw_input.strip().lower()
    if not raw_input.startswith(("http://", "https://")):
        raw_input = "http://" + raw_input

    parsed = urlparse(raw_input)
    hostname = parsed.hostname

    if not hostname:
        hostname = re.sub(r"^https?://", "", raw_input)
        hostname = hostname.split("/")[0].split(":")[0]

    return hostname

class VoidReconOPEngine:
    def __init__(self, target: str):
        self.raw_target = target
        self.target = clean_target_input(target)
        self.ip_address = ""
        self.risk_score = 0
        self.results: Dict[str, Any] = {
            "input_provided": target,
            "target_domain": self.target,
            "ip": "",
            "risk_score": 0,
            "geo_info": {},
            "http_info": {},
            "security_headers": {},
            "tech_stack": [],
            "ssl_info": {},
            "shodan_intel": {},
            "sensitive_endpoints": [],
            "open_ports": [],
            "subdomains": []
        }

    def resolve_target(self) -> bool:
        """Resolves target hostname to IPv4 address."""
        try:
            self.ip_address = socket.gethostbyname(self.target)
            self.results["ip"] = self.ip_address
            return True
        except socket.gaierror:
            return False

    def fetch_shodan_internetdb(self) -> None:
        """Queries Shodan's free InternetDB API for vulnerabilities and infrastructure tags."""
        try:
            url = f"https://internetdb.shodan.io/{self.ip_address}"
            req = urllib.request.Request(url, headers={'User-Agent': 'VoidRecon/4.0'})
            with urllib.request.urlopen(req, timeout=4) as response:
                data = json.loads(response.read().decode())
                vulns = data.get("vulns", [])
                tags = data.get("tags", [])
                cpes = data.get("cpes", [])

                self.results["shodan_intel"] = {
                    "vulnerabilities": vulns,
                    "tags": tags,
                    "cpes": cpes
                }
                
                # Risk calculation factor
                if vulns:
                    self.risk_score += len(vulns) * 15
        except Exception as e:
            logging.error(f"Shodan InternetDB query failed: {e}")

    def fetch_geolocation(self) -> None:
        """Fetches IP geolocation intelligence."""
        try:
            url = f"http://ip-api.com/json/{self.ip_address}"
            req = urllib.request.Request(url, headers={'User-Agent': 'VoidRecon/4.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    self.results["geo_info"] = {
                        "country": data.get("country", "N/A"),
                        "city": data.get("city", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org", "N/A")
                    }
        except Exception as e:
            logging.error(f"GeoIP failed: {e}")

    def fetch_ssl_certificate_info(self) -> None:
        """Extracts SSL/TLS certificate metadata."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    sans = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                    
                    self.results["ssl_info"] = {
                        "issuer": issuer.get('organizationName', 'Unknown Issuer'),
                        "not_after": cert.get('notAfter', 'N/A'),
                        "sans_count": len(sans),
                        "sans_sample": sans[:5]
                    }
        except Exception as e:
            logging.error(f"SSL Inspection failed: {e}")

    def inspect_web_tech_and_headers(self) -> None:
        """Audits security headers and detects web framework/technologies."""
        try:
            target_url = f"https://{self.target}"
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=4) as response:
                headers = dict(response.headers)
                content = response.read(2048).decode('utf-8', errors='ignore')
                
                title_search = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                page_title = title_search.group(1).strip() if title_search else "No Title Found"

                # Security Headers Check
                sec_headers = {
                    "Strict-Transport-Security (HSTS)": "Strict-Transport-Security" in headers,
                    "Content-Security-Policy (CSP)": "Content-Security-Policy" in headers,
                    "X-Frame-Options": "X-Frame-Options" in headers,
                    "X-Content-Type-Options": "X-Content-Type-Options" in headers
                }

                # Missing headers add to risk score
                for present in sec_headers.values():
                    if not present:
                        self.risk_score += 5

                # Tech Stack Fingerprinting
                tech_stack = []
                x_powered = headers.get('X-Powered-By', '')
                server_hdr = headers.get('Server', '')
                cookies = str(headers.get('Set-Cookie', ''))

                if x_powered: tech_stack.append(f"Powered-By: {x_powered}")
                if "PHPSESSID" in cookies: tech_stack.append("PHP Application")
                if "JSESSIONID" in cookies: tech_stack.append("Java/Tomcat")
                if "laravel_session" in cookies: tech_stack.append("Laravel Framework")
                if "express" in x_powered.lower(): tech_stack.append("Node.js / Express")
                if "wp-content" in content: tech_stack.append("WordPress CMS")

                # WAF Detection
                waf_detected = "None / Direct Server"
                if "cloudflare" in server_hdr.lower() or "__cfduid" in cookies:
                    waf_detected = "Cloudflare WAF"
                elif "fastly" in server_hdr.lower():
                    waf_detected = "Fastly CDN/WAF"
                elif "akamai" in server_hdr.lower():
                    waf_detected = "Akamai CDN"

                self.results["http_info"] = {
                    "status_code": response.status,
                    "server": server_hdr if server_hdr else 'Protected / Hidden',
                    "waf": waf_detected,
                    "page_title": page_title[:60]
                }
                self.results["security_headers"] = sec_headers
                self.results["tech_stack"] = tech_stack
        except Exception as e:
            logging.error(f"HTTP inspection failed: {e}")

    async def scan_sensitive_endpoints(self) -> None:
        """Checks for exposed sensitive files and endpoints."""
        paths = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/admin", "/phpinfo.php", "/api/v1"]
        semaphore = asyncio.Semaphore(10)

        async def _check_path(path: str):
            async with semaphore:
                try:
                    url = f"https://{self.target}{path}"
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    loop = asyncio.get_event_loop()
                    def _do_req():
                        try:
                            with urllib.request.urlopen(req, timeout=2.5) as resp:
                                return resp.status
                        except urllib.error.HTTPError as e:
                            return e.code
                        except Exception:
                            return 0

                    status = await loop.run_in_executor(None, _do_req)
                    if status in [200, 301, 302, 403]:
                        self.results["sensitive_endpoints"].append({"path": path, "status": status})
                        if path in ["/.env", "/.git/config"] and status == 200:
                            self.risk_score += 40
                except Exception:
                    pass

        tasks = [_check_path(p) for p in paths]
        await asyncio.gather(*tasks)

    def passive_subdomain_enum_crtsh(self) -> List[str]:
        """Fetches subdomains passively from Certificate Transparency Logs."""
        found_subs = set()
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'VoidRecon/4.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                for item in data:
                    name_value = item.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(self.target) and not sub.startswith('*'):
                            found_subs.add(sub)
        except Exception as e:
            logging.error(f"crt.sh enum failed: {e}")
        return list(found_subs)

    async def scan_extended_ports(self) -> None:
        """Asynchronously scans high-value target ports."""
        extended_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            1433, 1521, 2082, 2083, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017
        ]
        semaphore = asyncio.Semaphore(100)

        async def _check_port(port: int):
            async with semaphore:
                try:
                    conn = asyncio.open_connection(self.ip_address, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                    
                    try:
                        service = socket.getservbyport(port).upper()
                    except OSError:
                        service = "CUSTOM/UNKNOWN"

                    self.results["open_ports"].append({"port": port, "service": service})
                    if port in [21, 23, 3389, 6379, 27017]:  # High risk ports
                        self.risk_score += 10
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        tasks = [_check_port(p) for p in extended_ports]
        await asyncio.gather(*tasks)

    async def verify_subdomains(self, subdomains_list: List[str]) -> None:
        """Resolves passively collected subdomains."""
        semaphore = asyncio.Semaphore(150)

        async def _check_subdomain(full_domain: str):
            async with semaphore:
                loop = asyncio.get_event_loop()
                try:
                    ip = await loop.run_in_executor(None, socket.gethostbyname, full_domain)
                    self.results["subdomains"].append({"domain": full_domain, "ip": ip})
                except Exception:
                    pass

        tasks = [_check_subdomain(sub) for sub in subdomains_list[:30]]
        await asyncio.gather(*tasks)

    def render_dashboard(self) -> None:
        """Displays OVERPOWERED intelligence dashboard."""
        self.results["risk_score"] = min(self.risk_score, 100)
        
        # Risk Badge Color
        score_color = "green" if self.risk_score < 25 else "yellow" if self.risk_score < 60 else "bold red"

        console.print(Panel.fit(
            f"[bold cyan]⚡ VOID-RECON v4.0 (OVERPOWERED ENGINE)[/bold cyan]\n"
            f"[dim]Attack Surface Intelligence & Shodan Threat Profiler[/dim]\n"
            f"Calculated Risk Score: [{score_color}]{self.results['risk_score']} / 100[/{score_color}]",
            border_style="magenta"
        ))

        # Main Target Profile Tree
        tree = Tree(f"[bold yellow]🎯 Target Asset: {self.target}[/bold yellow] [dim](Input: {self.raw_target})[/dim]")
        tree.add(f"🌐 [cyan]Resolved IPv4:[/cyan] [bold white]{self.ip_address}[/bold white]")
        
        # Geo Profile
        geo = self.results.get("geo_info", {})
        if geo:
            geo_node = tree.add("📍 [cyan]Infrastructure & Geolocation[/cyan]")
            geo_node.add(f"Location: [white]{geo.get('city')}, {geo.get('country')}[/white]")
            geo_node.add(f"Provider: [white]{geo.get('isp')} ({geo.get('org')})[/white]")

        # Shodan Threat Intel
        shodan = self.results.get("shodan_intel", {})
        if shodan.get("vulnerabilities") or shodan.get("tags"):
            shodan_node = tree.add("💥 [bold red]Shodan Threat & CVE Intelligence[/bold red]")
            if shodan.get("tags"):
                shodan_node.add(f"Infrastructure Tags: [yellow]{', '.join(shodan.get('tags'))}[/yellow]")
            if shodan.get("vulnerabilities"):
                vuln_str = ", ".join(shodan.get("vulnerabilities")[:5])
                shodan_node.add(f"Known CVEs ({len(shodan.get('vulnerabilities'))}): [bold red]{vuln_str}[/bold red]")

        # Web Profile & Tech Stack Node
        web = self.results.get("http_info", {})
        if web:
            web_node = tree.add("🌐 [cyan]Web Fingerprint & Stack[/cyan]")
            web_node.add(f"Title: [white]{web.get('page_title')}[/white]")
            web_node.add(f"Server: [yellow]{web.get('server')}[/yellow]")
            web_node.add(f"WAF Shield: [bold magenta]{web.get('waf')}[/bold magenta]")
            if self.results["tech_stack"]:
                web_node.add(f"Detected Stack: [green]{', '.join(self.results['tech_stack'])}[/green]")

        console.print(tree)
        console.print()

        # Sensitive Endpoints Table
        if self.results["sensitive_endpoints"]:
            ep_table = Table(title="🔍 Discovered Sensitive Endpoints", header_style="bold yellow")
            ep_table.add_column("Path / Endpoint", style="white")
            ep_table.add_column("HTTP Status", justify="center")

            for ep in self.results["sensitive_endpoints"]:
                status_style = "green" if ep["status"] == 200 else "yellow"
                ep_table.add_row(ep["path"], f"[{status_style}]{ep['status']}[/{status_style}]")
            console.print(ep_table)
            console.print()

        # Security Headers Audit Table
        sec_h = self.results.get("security_headers", {})
        if sec_h:
            sec_table = Table(title="🛡️ Security Headers Audit", header_style="bold cyan")
            sec_table.add_column("Security Header Policy", style="white")
            sec_table.add_column("Audit Status", justify="center")

            for header_name, status in sec_h.items():
                status_str = "[bold green]PASS (PRESENT)[/bold green]" if status else "[bold red]FAIL (MISSING)[/bold red]"
                sec_table.add_row(header_name, status_str)
            console.print(sec_table)
            console.print()

        # Open Ports Table
        if self.results["open_ports"]:
            port_table = Table(title="🔓 Open Attack Surface Ports", header_style="bold green")
            port_table.add_column("Port", justify="center", style="yellow")
            port_table.add_column("Active Service", style="cyan")

            for item in sorted(self.results["open_ports"], key=lambda x: x["port"]):
                port_table.add_row(str(item["port"]), item["service"])
            console.print(port_table)

        console.print()

        # Passive Subdomain Table
        if self.results["subdomains"]:
            sub_table = Table(title=f"📡 Active Subdomains Discovered ({len(self.results['subdomains'])})", header_style="bold magenta")
            sub_table.add_column("Verified Subdomain", style="white")
            sub_table.add_column("Resolved IP", style="green")

            for sub in self.results["subdomains"][:10]:
                sub_table.add_row(sub["domain"], sub["ip"])
            console.print(sub_table)

        # Export JSON
        with open("void_report.json", "w") as f:
            json.dump(self.results, f, indent=4)
        console.print("\n[bold green]✅ OVERPOWERED Recon complete! Report saved to void_report.json[/bold green]\n")

async def main():
    parser = argparse.ArgumentParser(description="VoidRecon v4.0: Overpowered OSINT & Threat Engine")
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain")
    args = parser.parse_args()

    engine = VoidReconOPEngine(target=args.target)
    
    console.print(f"[bold magenta]--> [v4.0 OP ENGINE INITIATED][/bold magenta] Analyzing '[bold green]{engine.target}[/bold green]'...")

    if not engine.resolve_target():
        console.print(f"[bold red]Error:[/bold red] Could not resolve host '{engine.target}'.")
        sys.exit(1)

    console.print("[cyan]--> Fetching Geolocation OSINT...[/cyan]")
    engine.fetch_geolocation()

    console.print("[cyan]--> Querying Shodan Threat & Vulnerability Database...[/cyan]")
    engine.fetch_shodan_internetdb()

    console.print("[cyan]--> Extracting SSL/TLS Certificate Intelligence...[/cyan]")
    engine.fetch_ssl_certificate_info()

    console.print("[cyan]--> Auditing Web Application, Tech Stack & Headers...[/cyan]")
    engine.inspect_web_tech_and_headers()

    console.print("[cyan]--> Bruteforcing Sensitive Endpoints (.env, .git, etc)...[/cyan]")
    await engine.scan_sensitive_endpoints()

    console.print("[cyan]--> Executing Async Port Scan...[/cyan]")
    await engine.scan_extended_ports()

    console.print("[cyan]--> Mining Certificate Transparency Logs for Subdomains...[/cyan]")
    passive_subs = engine.passive_subdomain_enum_crtsh()
    if passive_subs:
        await engine.verify_subdomains(passive_subs)

    engine.render_dashboard()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation canceled by user.[/bold red]")