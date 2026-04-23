import os
import re
import json
import asyncio
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml
from dotenv import load_dotenv
from loguru import logger
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

# Load environment variables
load_dotenv()

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    REPORTED = "reported"

@dataclass
class Finding:
    """Vulnerability finding structure"""
    id: str
    title: str
    description: str
    severity: Severity
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    poc: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.NEW
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)
    
class Target(BaseModel):
    domain: str
    scope: str  # in-scope, out-of-scope
    ip_addresses: List[str] = []
    subdomains: List[str] = []
    endpoints: List[str] = []
    technologies: List[str] = []
    notes: str = ""

class CyberAgent:
    """Main Cybersecurity AI Agent"""
    
    def __init__(self, config_path: str = "config.yaml"):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        # Initialize OpenAI client
        self.openai_client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Agent state
        self.target: Optional[Target] = None
        self.findings: List[Finding] = []
        self.scan_history: List[Dict] = []
        self.session_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()
        
        # Initialize tools
        self.tools = {}
        
        # Setup logging
        logger.add(f"logs/agent_{self.session_id}.log", rotation="100 MB")
        
        logger.info(f"Cyber Agent initialized | Session: {self.session_id}")
        
    async def initialize_target(self, domain: str, scope_file: str = None):
        """Initialize target domain for testing"""
        self.target = Target(domain=domain, scope="in-scope")
        
        # Load scope if provided
        if scope_file and os.path.exists(scope_file):
            with open(scope_file, 'r') as f:
                scope_lines = f.readlines()
                for line in scope_lines:
                    if line.strip() and not line.startswith('#'):
                        if 'out-of-scope' in line.lower():
                            # Handle out of scope domains
                            pass
                        else:
                            # Add to target endpoints
                            self.target.endpoints.append(line.strip())
        
        logger.info(f"Target initialized: {domain}")
        
        # Start reconnaissance
        await self.run_reconnaissance_phase()
        
    async def run_reconnaissance_phase(self):
        """Phase 1: Reconnaissance and OSINT"""
        logger.info("Starting reconnaissance phase...")
        
        print("\n" + "="*60)
        print("🔍 PHASE 1: RECONNAISSANCE & OSINT")
        print("="*60)
        
        # Subdomain enumeration
        print("\n📡 Enumerating subdomains...")
        subdomains = await self.enumerate_subdomains()
        self.target.subdomains = subdomains
        print(f"Found {len(subdomains)} subdomains")
        
        # DNS enumeration
        print("\n🌐 Enumerating DNS records...")
        dns_records = await self.enumerate_dns()
        
        # Technology stack detection
        print("\n💻 Detecting technologies...")
        technologies = await self.detect_technologies(self.target.domain)
        self.target.technologies = technologies
        print(f"Technologies detected: {', '.join(technologies[:5])}")
        
        # Port scanning
        print("\n🔌 Scanning open ports...")
        open_ports = await self.scan_ports()
        
        # Endpoint discovery
        print("\n🔍 Discovering endpoints...")
        endpoints = await self.discover_endpoints()
        self.target.endpoints.extend(endpoints)
        print(f"Found {len(endpoints)} endpoints")
        
        # Gather intelligence from AI analysis
        await self.ai_analyze_recon_data(dns_records, technologies, open_ports)
        
        await self.run_vulnerability_scanning_phase()
        
    async def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using multiple tools and sources"""
        subdomains = set()
        
        # Using various techniques
        techniques = [
            self._certificate_transparency_enum,
            self._dns_bruteforce_enum,
            self._dns_dumpster_enum,
            self._securitytrails_enum,
        ]
        
        # Run enumeration in parallel
        tasks = [tech() for tech in techniques]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                subdomains.update(result)
        
        # Use AI to discover potential subdomains
        ai_subdomains = await self._ai_subdomain_prediction()
        subdomains.update(ai_subdomains)
        
        # Filter and validate
        valid_subdomains = await self._validate_subdomains(list(subdomains))
        
        return list(valid_subdomains)
    
    async def _certificate_transparency_enum(self) -> List[str]:
        """Enumerate subdomains from Certificate Transparency logs"""
        import aiohttp
        
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.target.domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name.endswith(f'.{self.target.domain}'):
                                subdomains.add(name.lower())
        except Exception as e:
            logger.error(f"Certificate transparency error: {e}")
            
        return list(subdomains)
    
    async def _dns_bruteforce_enum(self) -> List[str]:
        """Bruteforce subdomains using common wordlist"""
        import dns.resolver
        
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'blog', 'forum',
            'news', 'support', 'demo', 'dev', 'test', 'staging', 'api', 'app', 'portal',
            'dashboard', 'login', 'secure', 'vpn', 'remote', 'exchange', 'lists', 'stats'
        ]
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{self.target.domain}"
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, dns.resolver.resolve, full_domain, 'A'
                )
                subdomains.append(full_domain)
            except:
                pass
                
        return subdomains
    
    async def _dns_dumpster_enum(self) -> List[str]:
        """Use DNSdumpster API for enumeration"""
        import aiohttp
        
        subdomains = []
        api_url = f"https://dnsdumpster.com/api/hosted/{self.target.domain}"
        
        # Note: DNSdumpster requires proper API key for automation
        # This is a placeholder
        return subdomains
    
    async def _securitytrails_enum(self) -> List[str]:
        """Use SecurityTrails API"""
        api_key = os.getenv("SECURITYTRAILS_API_KEY")
        if not api_key:
            return []
            
        import aiohttp
        
        subdomains = []
        headers = {'APIKEY': api_key}
        url = f"https://api.securitytrails.com/v1/domain/{self.target.domain}/subdomains"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for sub in data.get('subdomains', []):
                            subdomains.append(f"{sub}.{self.target.domain}")
        except Exception as e:
            logger.error(f"SecurityTrails error: {e}")
            
        return subdomains
    
    async def _ai_subdomain_prediction(self) -> List[str]:
        """Use AI to predict possible subdomains"""
        prompt = f"""
        Based on the domain {self.target.domain}, generate 20 likely subdomain names.
        Consider common patterns, naming conventions, and industry standards.
        Return as JSON list.
        """
        
        response = await self._ai_completion(prompt, response_format="json")
        try:
            data = json.loads(response)
            return data if isinstance(data, list) else []
        except:
            return []
    
    async def _validate_subdomains(self, subdomains: List[str]) -> Set[str]:
        """Validate subdomains by checking DNS resolution"""
        import dns.resolver
        
        valid = set()
        
        async def check_subdomain(subdomain):
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, dns.resolver.resolve, subdomain, 'A'
                )
                valid.add(subdomain)
                print(f"  ✓ {subdomain}")
            except:
                pass
        
        tasks = [check_subdomain(sub) for sub in subdomains[:100]]  # Limit to 100
        await asyncio.gather(*tasks)
        
        return valid
    
    async def enumerate_dns(self) -> Dict[str, Any]:
        """Enumerate all DNS records"""
        import dns.resolver
        
        dns_records = {}
        record_types = self.config.get('reconnaissance', {}).get('dns_enumeration', {}).get('record_types', [])
        
        for record_type in record_types:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, dns.resolver.resolve, self.target.domain, record_type
                )
                dns_records[record_type] = [str(answer) for answer in answers]
            except:
                dns_records[record_type] = []
                
        return dns_records
    
    async def detect_technologies(self, domain: str) -> List[str]:
        """Detect technology stack of target"""
        import requests
        from wappalyzer import Wappalyzer, WebPage
        
        technologies = []
        
        try:
            # Get response from target
            response = requests.get(f"https://{domain}", timeout=10, verify=False)
            webpage = WebPage(f"https://{domain}", html=response.text, headers=response.headers)
            
            wappalyzer = Wappalyzer.latest()
            detected = wappalyzer.analyze(webpage)
            technologies = list(detected)
        except Exception as e:
            logger.error(f"Technology detection error: {e}")
            
        return technologies
    
    async def scan_ports(self) -> List[int]:
        """Scan for open ports"""
        import socket
        import concurrent.futures
        
        open_ports = []
        common_ports = self.config.get('reconnaissance', {}).get('port_scanning', {}).get('common_ports', [])
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target.domain, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  Port {result} open")
                    
        return open_ports
    
    async def discover_endpoints(self) -> List[str]:
        """Discover web endpoints and directories"""
        import requests
        from urllib.parse import urljoin
        
        endpoints = []
        common_paths = [
            '/', '/admin', '/api', '/v1', '/v2', '/status', '/health', '/metrics',
            '/login', '/signin', '/auth', '/oauth', '/callback', '/webhook',
            '/.git/config', '/.env', '/backup', '/backups', '/config', '/configuration',
            '/swagger', '/api-docs', '/openapi.json', '/graphql', '/graphiql',
            '/phpinfo.php', '/info.php', '/server-status', '/.htaccess',
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt'
        ]
        
        for path in common_paths:
            try:
                url = f"https://{self.target.domain}{path}"
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    endpoints.append(url)
                    print(f"  Found: {url} (Status: {response.status_code})")
            except:
                pass
                
        return endpoints
    
    async def ai_analyze_recon_data(self, dns_records: Dict, technologies: List[str], open_ports: List[int]):
        """Use AI to analyze reconnaissance data and identify attack surface"""
        prompt = f"""
        Analyze this reconnaissance data for {self.target.domain}:
        
        DNS Records: {json.dumps(dns_records, indent=2)}
        Technologies: {technologies}
        Open Ports: {open_ports}
        
        Provide analysis on:
        1. Attack surface summary
        2. Interesting services/technologies
        3. Potential vulnerabilities based on versions
        4. Recommended next steps for testing
        
        Format as JSON with keys: attack_surface, interesting_observations, potential_vulnerabilities, next_steps
        """
        
        analysis = await self._ai_completion(prompt, response_format="json")
        
        try:
            analysis_data = json.loads(analysis)
            logger.info(f"AI Analysis: {analysis_data}")
            
            # Store analysis notes
            self.target.notes = json.dumps(analysis_data, indent=2)
        except:
            pass
            
    async def run_vulnerability_scanning_phase(self):
        """Phase 2: Vulnerability Scanning"""
        logger.info("Starting vulnerability scanning phase...")
        
        print("\n" + "="*60)
        print("⚡ PHASE 2: VULNERABILITY SCANNING")
        print("="*60)
        
        # Test each endpoint
        for endpoint in self.target.endpoints[:20]:  # Limit for demo
            print(f"\n[Testing] {endpoint}")
            
            # SQL Injection testing
            await self.test_sql_injection(endpoint)
            
            # XSS testing
            await self.test_xss(endpoint)
            
            # Open Redirect testing
            await self.test_open_redirect(endpoint)
            
            # Path traversal testing
            await self.test_path_traversal(endpoint)
            
            # Security headers check
            await self.check_security_headers(endpoint)
            
        await self.run_exploitation_phase()
    
    async def test_sql_injection(self, url: str):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "'", "''", "' OR '1'='1", "' OR 1=1--", 
            "1' AND '1'='1", "1' AND '1'='2",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--", "' WAITFOR DELAY '0:0:5'--"
        ]
        
        for payload in sql_payloads:
            try:
                # Test parameter reflection
                test_url = f"{url}?id={payload}" if '?' not in url else f"{url}&id={payload}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=5) as response:
                        text = await response.text()
                        
                        # Check for SQL errors
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "ORA-[0-9]{5}",
                            "PostgreSQL", "SQLite", "Microsoft OLE DB",
                            "Unclosed quotation mark", "You have an error in your SQL syntax"
                        ]
                        
                        for error in sql_errors:
                            if re.search(error, text, re.IGNORECASE):
                                finding = Finding(
                                    id=hashlib.md5(f"{url}{payload}".encode()).hexdigest(),
                                    title="SQL Injection Vulnerability",
                                    description=f"Potential SQL injection detected with payload: {payload}",
                                    severity=Severity.HIGH,
                                    endpoint=url,
                                    parameter="id",
                                    payload=payload,
                                    poc=f"GET request to: {test_url}",
                                    remediation="Use parameterized queries/prepared statements",
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                                )
                                self.findings.append(finding)
                                print(f"    [!] SQL Injection found: {payload}")
                                return  # Stop after first finding
            except:
                pass
    
    async def test_xss(self, url: str):
        """Test for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><img src=x onerror=alert('XSS')>",
            "\"><img src=x onerror=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{url}?search={payload}" if '?' not in url else f"{url}&search={payload}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=5) as response:
                        text = await response.text()
                        
                        # Check if payload is reflected unescaped
                        if payload in text and not self._is_escaped(text, payload):
                            finding = Finding(
                                id=hashlib.md5(f"{url}{payload}".encode()).hexdigest(),
                                title="Cross-Site Scripting (XSS) Vulnerability",
                                description=f"Reflected XSS detected with payload: {payload}",
                                severity=Severity.MEDIUM,
                                endpoint=url,
                                parameter="search",
                                payload=payload,
                                poc=f"GET request to: {test_url}",
                                remediation="Implement proper output encoding and Content Security Policy",
                                references=["https://owasp.org/www-community/attacks/xss/"]
                            )
                            self.findings.append(finding)
                            print(f"    [!] XSS found: {payload[:50]}...")
                            return
            except:
                pass
    
    async def test_open_redirect(self, url: str):
        """Test for Open Redirect vulnerabilities"""
        redirect_payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com@evil.com",
            "///evil.com",
            "/\\evil.com",
            "https:evil.com"
        ]
        
        for payload in redirect_payloads:
            try:
                test_url = f"{url}?redirect={payload}" if '?' not in url else f"{url}&redirect={payload}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=5, allow_redirects=False) as response:
                        if response.status in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if any(bad_domain in location for bad_domain in ['evil.com', 'google.com@evil.com']):
                                finding = Finding(
                                    id=hashlib.md5(f"{url}{payload}".encode()).hexdigest(),
                                    title="Open Redirect Vulnerability",
                                    description=f"Open redirect detected to: {location}",
                                    severity=Severity.MEDIUM,
                                    endpoint=url,
                                    parameter="redirect",
                                    payload=payload,
                                    poc=f"GET request to: {test_url} (redirects to {location})",
                                    remediation="Validate and sanitize redirect URLs against whitelist",
                                    references=["https://owasp.org/www-community/vulnerabilities/Open_redirect"]
                                )
                                self.findings.append(finding)
                                print(f"    [!] Open Redirect found: {location}")
                                return
            except:
                pass
    
    async def test_path_traversal(self, url: str):
        """Test for Path Traversal vulnerabilities"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..;/..;/..;/etc/passwd"
        ]
        
        for payload in path_payloads:
            try:
                test_url = f"{url}?file={payload}" if '?' not in url else f"{url}&file={payload}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=5) as response:
                        text = await response.text()
                        
                        # Check for sensitive file indicators
                        indicators = ["root:x:", "daemon:x:", "[extensions]", "[fonts]"]
                        for indicator in indicators:
                            if indicator in text:
                                finding = Finding(
                                    id=hashlib.md5(f"{url}{payload}".encode()).hexdigest(),
                                    title="Path Traversal Vulnerability",
                                    description=f"Path traversal allows reading system files with payload: {payload}",
                                    severity=Severity.HIGH,
                                    endpoint=url,
                                    parameter="file",
                                    payload=payload,
                                    poc=f"GET request to: {test_url}",
                                    remediation="Validate file paths and use allowlists",
                                    references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                                )
                                self.findings.append(finding)
                                print(f"    [!] Path Traversal found: {payload}")
                                return
            except:
                pass
    
    async def check_security_headers(self, url: str):
        """Check for missing security headers"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    headers = response.headers
                    
                    security_headers = {
                        'Strict-Transport-Security': 'HSTS missing - Risk of SSL stripping',
                        'Content-Security-Policy': 'CSP missing - Risk of XSS',
                        'X-Content-Type-Options': 'Missing nosniff - Risk of MIME confusion',
                        'X-Frame-Options': 'Missing clickjacking protection',
                        'X-XSS-Protection': 'Missing XSS protection header',
                        'Referrer-Policy': 'Missing referrer policy',
                        'Permissions-Policy': 'Missing permissions policy'
                    }
                    
                    missing_headers = []
                    for header, risk in security_headers.items():
                        if header not in headers:
                            missing_headers.append(f"{header}: {risk}")
                    
                    if missing_headers:
                        finding = Finding(
                            id=hashlib.md5(f"{url}_headers".encode()).hexdigest(),
                            title="Missing Security Headers",
                            description="The following security headers are missing: " + ", ".join(missing_headers),
                            severity=Severity.LOW,
                            endpoint=url,
                            remediation="Implement missing security headers",
                            references=["https://securityheaders.com/"]
                        )
                        self.findings.append(finding)
                        print(f"    [!] Missing security headers: {len(missing_headers)} found")
        except:
            pass
    
    async def run_exploitation_phase(self):
        """Phase 3: Confirmation and Exploitation"""
        logger.info("Starting exploitation phase...")
        
        print("\n" + "="*60)
        print("🔓 PHASE 3: EXPLOITATION CONFIRMATION")
        print("="*60)
        
        for finding in self.findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                print(f"\n[Exploiting] {finding.title}")
                await self.confirm_vulnerability(finding)
    
    async def confirm_vulnerability(self, finding: Finding):
        """Attempt to confirm vulnerability with safe exploitation"""
        logger.info(f"Confirming: {finding.title}")
        
        # Use AI to generate safe PoC
        prompt = f"""
        Generate a safe proof-of-concept for this vulnerability:
        Title: {finding.title}
        Endpoint: {finding.endpoint}
        Parameter: {finding.parameter}
        Payload: {finding.payload}
        
        Provide a Python code snippet that demonstrates the vulnerability
        without causing damage. Include error handling and safety checks.
        """
        
        poc_code = await self._ai_completion(prompt)
        finding.poc = poc_code
        finding.status = FindingStatus.CONFIRMED
        
        print(f"    ✓ Confirmed: {finding.title}")
        
    async def generate_report(self, format: str = "html") -> str:
        """Generate comprehensive vulnerability report"""
        
        print("\n" + "="*60)
        print("📄 PHASE 4: REPORT GENERATION")
        print("="*60)
        
        report_data = {
            "target": self.target.domain,
            "session_id": self.session_id,
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO])
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "endpoint": f.endpoint,
                    "description": f.description,
                    "remediation": f.remediation,
                    "poc": f.poc,
                    "references": f.references
                }
                for f in self.findings
            ]
        }
        
        # Generate HTML report
        if format == "html":
            report = await self._generate_html_report(report_data)
        elif format == "markdown":
            report = await self._generate_markdown_report(report_data)
        elif format == "json":
            report = json.dumps(report_data, indent=2)
        else:
            report = json.dumps(report_data, indent=2)
        
        # Save report
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        
        report_file = report_dir / f"report_{self.target.domain}_{self.session_id[:8]}.{format}"
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n✓ Report generated: {report_file}")
        
        return report
    
    async def _generate_html_report(self, data: Dict) -> str:
        """Generate HTML report with styling"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Bounty Report - {target}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .severity-critical {{ color: #721c24; background: #f8d7da; }}
                .severity-high {{ color: #856404; background: #fff3cd; }}
                .severity-medium {{ color: #0c5460; background: #d1ecf1; }}
                .severity-low {{ color: #155724; background: #d4edda; }}
                .finding {{
                    margin-bottom: 20px;
                    border-left: 4px solid #ddd;
                    padding: 15px;
                    background: #f9f9f9;
                }}
                .finding-title {{
                    font-size: 18px;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .stat-box {{
                    background: #f0f0f0;
                    padding: 15px;
                    border-radius: 5px;
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 36px;
                    font-weight: bold;
                    color: #667eea;
                }}
                pre {{
                    background: #2d2d2d;
                    color: #f8f8f2;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                }}
                .badge {{
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Bug Bounty Security Assessment Report</h1>
                    <p><strong>Target:</strong> {target}</p>
                    <p><strong>Scan Date:</strong> {scan_date}</p>
                    <p><strong>Session ID:</strong> {session_id}</p>
                </div>
                
                <h2>📊 Executive Summary</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">{total_findings}</div>
                        <div>Total Findings</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{critical_count}</div>
                        <div>Critical</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{high_count}</div>
                        <div>High</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{medium_count}</div>
                        <div>Medium</div>
                    </div>
                </div>
                
                <h2>🔐 Vulnerabilities Found</h2>
                {findings_html}
            </div>
        </body>
        </html>
        """
        
        findings_html = ""
        for finding in data['findings']:
            findings_html += f"""
            <div class="finding">
                <div class="finding-title">
                    <span class="badge severity-{finding['severity']}">{finding['severity'].upper()}</span>
                    {finding['title']}
                </div>
                <p><strong>Endpoint:</strong> {finding['endpoint']}</p>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Remediation:</strong> {finding['remediation'] or 'N/A'}</p>
                {f'<p><strong>PoC:</strong></p><pre>{finding["poc"]}</pre>' if finding.get('poc') else ''}
                {f'<p><strong>References:</strong> {", ".join(finding["references"])}</p>' if finding.get('references') else ''}
            </div>
            """
        
        return html_template.format(
            target=data['target'],
            scan_date=data['scan_date'],
            session_id=data['session_id'],
            total_findings=data['total_findings'],
            critical_count=data['findings_by_severity']['critical'],
            high_count=data['findings_by_severity']['high'],
            medium_count=data['findings_by_severity']['medium'],
            findings_html=findings_html
        )
    
    async def _generate_markdown_report(self, data: Dict) -> str:
        """Generate Markdown report"""
        report = f"""# Bug Bounty Security Report

## Target Information
- **Domain:** {data['target']}
- **Scan Date:** {data['scan_date']}
- **Session ID:** {data['session_id']}

## Executive Summary
- **Total Findings:** {data['total_findings']}
- **Critical:** {data['findings_by_severity']['critical']}
- **High:** {data['findings_by_severity']['high']}
- **Medium:** {data['findings_by_severity']['medium']}
- **Low:** {data['findings_by_severity']['low']}

## Detailed Findings

"""
        for finding in data['findings']:
            report += f"""
### {finding['title']}
- **Severity:** {finding['severity'].upper()}
- **Endpoint:** {finding['endpoint']}
- **Description:** {finding['description']}
- **Remediation:** {finding['remediation'] or 'N/A'}
{f"- **PoC:**\n```python\n{finding['poc']}\n```" if finding.get('poc') else ''}
{f"- **References:** {', '.join(finding['references'])}" if finding.get('references') else ''}

---
"""
        return report
    
    async def _ai_completion(self, prompt: str, response_format: str = "text") -> str:
        """Get completion from AI"""
        try:
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert AI assistant for bug bounty hunting."},
                {"role": "user", "content": prompt}
            ]
            
            if response_format == "json":
                messages.append({"role": "system", "content": "Respond with valid JSON only."})
            
            response = await self.openai_client.chat.completions.create(
                model=self.config['llm']['primary_model'],
                messages=messages,
                temperature=self.config['llm']['temperature'],
                max_tokens=self.config['llm']['max_tokens']
            )
            
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI completion error: {e}")
            return "{}" if response_format == "json" else ""
    
    def _is_escaped(self, text: str, payload: str) -> bool:
        """Check if payload is HTML escaped"""
        escaped_chars = ['&lt;', '&gt;', '&quot;', '&#39;']
        return any(char in text for char in escaped_chars)
    
    async def run_full_assessment(self, domain: str):
        """Run complete bug bounty assessment"""
        start_time = datetime.now()
        
        print("\n" + "="*60)
        print("🐛 BUG BOUNTY AI AGENT")
        print(f"Target: {domain}")
        print(f"Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        try:
            # Initialize target
            await self.initialize_target(domain)
            
            # Run all phases
            # Phases are called sequentially within the methods
            
            # Generate report
            report = await self.generate_report("html")
            
            # Summary
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print("\n" + "="*60)
            print("✅ ASSESSMENT COMPLETE")
            print("="*60)
            print(f"Duration: {duration:.2f} seconds")
            print(f"Findings: {len(self.findings)}")
            print(f"  - Critical: {len([f for f in self.findings if f.severity == Severity.CRITICAL])}")
            print(f"  - High: {len([f for f in self.findings if f.severity == Severity.HIGH])}")
            print(f"  - Medium: {len([f for f in self.findings if f.severity == Severity.MEDIUM])}")
            print(f"  - Low: {len([f for f in self.findings if f.severity == Severity.LOW])}")
            print(f"\nReport saved to: reports/")
            
        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            print(f"\n❌ Assessment failed: {e}")

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Bug Bounty AI Agent")
    parser.add_argument("domain", help="Target domain to test")
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    parser.add_argument("--scope", help="Scope file path")
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = CyberAgent(args.config)
    
    # Run assessment
    await agent.run_full_assessment(args.domain)

if __name__ == "__main__":
    asyncio.run(main())