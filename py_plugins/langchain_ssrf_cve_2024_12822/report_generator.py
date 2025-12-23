#!/usr/bin/env python3
"""
Advanced HTML Report Generator for CVE-2024-12822

Generates comprehensive, professional HTML reports with:
- Executive summary
- Detailed findings
- PoC screenshots
- Remediation steps
- Interactive visualizations

Author: Tsunami Community
License: Apache 2.0
"""

import argparse
import json
import base64
from datetime import datetime
from typing import Dict, List, Optional


class SSRFReportGenerator:
    """Generate professional HTML reports for SSRF findings."""

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF Vulnerability Report - CVE-2024-12822</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .severity {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 5px;
            font-weight: bold;
            margin-top: 15px;
            font-size: 1.1em;
        }}
        
        .severity.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .card {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .card h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .card h3 {{
            color: #555;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-item {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .info-item label {{
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 8px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .info-item value {{
            color: #333;
            font-size: 1.1em;
        }}
        
        .finding {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        
        .finding.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        .finding.high {{
            background: #ffe5d0;
            border-left-color: #fd7e14;
        }}
        
        .finding h4 {{
            margin-bottom: 10px;
            color: #333;
        }}
        
        .code-block {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
        }}
        
        .code-block .comment {{
            color: #6a9955;
        }}
        
        .code-block .string {{
            color: #ce9178;
        }}
        
        .code-block .keyword {{
            color: #569cd6;
        }}
        
        .recommendations {{
            background: #d1ecf1;
            border-left: 5px solid #17a2b8;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        
        .recommendations li {{
            margin: 10px 0;
        }}
        
        .impact-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 8px;
        }}
        
        .impact-badge.confidentiality {{
            background: #dc3545;
            color: white;
        }}
        
        .impact-badge.integrity {{
            background: #ffc107;
            color: #333;
        }}
        
        .impact-badge.availability {{
            background: #17a2b8;
            color: white;
        }}
        
        .timeline {{
            position: relative;
            padding-left: 40px;
            margin-top: 20px;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: #667eea;
        }}
        
        .timeline-item {{
            position: relative;
            margin-bottom: 25px;
        }}
        
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -34px;
            top: 0;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #667eea;
            border: 3px solid white;
        }}
        
        .table-container {{
            overflow-x: auto;
            margin: 20px 0;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }}
        
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .progress-bar {{
            height: 30px;
            background: #e9ecef;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.3s ease;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .card {{
                box-shadow: none;
                border: 1px solid #ddd;
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Vulnerability Report</h1>
            <div class="subtitle">LangChain SSRF Vulnerability Assessment</div>
            <div class="subtitle">CVE-2024-12822</div>
            <span class="severity {severity_class}">{severity} SEVERITY</span>
        </div>
        
        <div class="card">
            <h2>📊 Executive Summary</h2>
            <p>{executive_summary}</p>
            
            <div class="info-grid">
                <div class="info-item">
                    <label>Target</label>
                    <value>{target_url}</value>
                </div>
                <div class="info-item">
                    <label>Scan Date</label>
                    <value>{scan_date}</value>
                </div>
                <div class="info-item">
                    <label>Vulnerability</label>
                    <value>CVE-2024-12822</value>
                </div>
                <div class="info-item">
                    <label>CVSS Score</label>
                    <value>{cvss_score} ({severity})</value>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🎯 Impact Assessment</h2>
            <div>
                <span class="impact-badge confidentiality">Confidentiality: HIGH</span>
                <span class="impact-badge integrity">Integrity: MEDIUM</span>
                <span class="impact-badge availability">Availability: LOW</span>
            </div>
            
            <h3>Potential Impact</h3>
            <ul>
                <li><strong>Data Exfiltration:</strong> Access to internal systems and cloud metadata</li>
                <li><strong>Credential Theft:</strong> Extraction of AWS/GCP/Azure credentials</li>
                <li><strong>Network Pivoting:</strong> Internal network reconnaissance</li>
                <li><strong>Cloud Account Compromise:</strong> Full cloud environment takeover</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>🔍 Technical Findings</h2>
            {findings_html}
        </div>
        
        <div class="card">
            <h2>💻 Proof of Concept</h2>
            <p>The following demonstrates the vulnerability exploitation:</p>
            {poc_html}
        </div>
        
        <div class="card">
            <h2>🛡️ Recommendations</h2>
            <div class="recommendations">
                <h3>Immediate Actions</h3>
                <ul>
                    <li><strong>Upgrade LangChain:</strong> Update to version 0.3.18 or later immediately</li>
                    <li><strong>Implement URL Allowlisting:</strong> Restrict document loader URLs to trusted domains</li>
                    <li><strong>Network Segmentation:</strong> Isolate application servers from cloud metadata endpoints</li>
                </ul>
            </div>
            
            <div class="recommendations">
                <h3>Long-term Mitigations</h3>
                <ul>
                    <li>Implement WAF rules to block SSRF attempts</li>
                    <li>Use IMDSv2 for AWS EC2 instances</li>
                    <li>Enable VPC endpoints for cloud services</li>
                    <li>Implement request validation and sanitization</li>
                    <li>Deploy network monitoring for unusual outbound connections</li>
                    <li>Regular security audits of LangChain configurations</li>
                </ul>
            </div>
        </div>
        
        <div class="card">
            <h2>📚 References</h2>
            <ul>
                <li><a href="https://nvd.nist.gov/vuln/detail/CVE-2024-12822" target="_blank">CVE-2024-12822 - NVD</a></li>
                <li><a href="https://github.com/langchain-ai/langchain" target="_blank">LangChain GitHub Repository</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/918.html" target="_blank">CWE-918: Server-Side Request Forgery</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank">OWASP SSRF</a></li>
            </ul>
        </div>
        
        <div class="card">
            <h2>📈 Remediation Timeline</h2>
            <div class="timeline">
                <div class="timeline-item">
                    <strong>Day 0 - Immediate</strong><br>
                    Upgrade LangChain to patched version
                </div>
                <div class="timeline-item">
                    <strong>Week 1</strong><br>
                    Implement URL allowlisting and input validation
                </div>
                <div class="timeline-item">
                    <strong>Week 2</strong><br>
                    Deploy network segmentation and monitoring
                </div>
                <div class="timeline-item">
                    <strong>Month 1</strong><br>
                    Complete security audit and penetration testing
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Tsunami Security Scanner - CVE-2024-12822 Detector</p>
            <p>Generated on {report_date}</p>
            <p>⚠️ This report contains sensitive security information - Handle with care</p>
        </div>
    </div>
</body>
</html>"""

    def __init__(self):
        """Initialize the report generator."""
        self.data = {
            "target_url": "",
            "severity": "HIGH",
            "findings": [],
            "poc_steps": [],
            "credentials_found": False,
        }

    def add_finding(
        self,
        title: str,
        description: str,
        severity: str = "high",
        details: Optional[Dict] = None
    ):
        """Add a security finding."""
        self.data["findings"].append({
            "title": title,
            "description": description,
            "severity": severity,
            "details": details or {}
        })

    def add_poc_step(self, step: str, code: Optional[str] = None, result: Optional[str] = None):
        """Add a PoC step."""
        self.data["poc_steps"].append({
            "step": step,
            "code": code,
            "result": result
        })

    def generate_findings_html(self) -> str:
        """Generate HTML for findings section."""
        if not self.data["findings"]:
            return "<p>No specific findings to display.</p>"
        
        html = ""
        for i, finding in enumerate(self.data["findings"], 1):
            html += f"""
            <div class="finding {finding['severity']}">
                <h4>Finding #{i}: {finding['title']}</h4>
                <p>{finding['description']}</p>
            """
            
            if finding.get('details'):
                html += "<h5>Details:</h5><ul>"
                for key, value in finding['details'].items():
                    html += f"<li><strong>{key}:</strong> {value}</li>"
                html += "</ul>"
            
            html += "</div>"
        
        return html

    def generate_poc_html(self) -> str:
        """Generate HTML for PoC section."""
        if not self.data["poc_steps"]:
            return "<p>No proof of concept steps recorded.</p>"
        
        html = "<div class='timeline'>"
        
        for step in self.data["poc_steps"]:
            html += f"""
            <div class="timeline-item">
                <strong>{step['step']}</strong><br>
            """
            
            if step.get('code'):
                html += f"""
                <div class="code-block">
                    <div class="comment"># Request</div>
                    {self._escape_html(step['code'])}
                </div>
                """
            
            if step.get('result'):
                html += f"""
                <div class="code-block">
                    <div class="comment"># Response</div>
                    {self._escape_html(step['result'][:500])}
                </div>
                """
            
            html += "</div>"
        
        html += "</div>"
        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

    def load_from_json(self, json_file: str):
        """Load findings from JSON file."""
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        self.data["target_url"] = data.get("target", "Unknown")
        
        # Parse findings from harvested data
        if data.get("aws", {}).get("credentials"):
            self.add_finding(
                "AWS Credentials Exposed",
                "Successfully extracted AWS IAM credentials via SSRF to instance metadata service.",
                severity="critical",
                details={
                    "AccessKeyId": data["aws"]["credentials"].get("AccessKeyId", "N/A")[:20] + "...",
                    "Role": data["aws"].get("iam_role", "N/A"),
                    "Region": data["aws"].get("region", "N/A")
                }
            )
            self.data["credentials_found"] = True
        
        if data.get("gcp", {}).get("token"):
            self.add_finding(
                "GCP Service Account Token Exposed",
                "Successfully extracted GCP service account access token via SSRF.",
                severity="critical"
            )
            self.data["credentials_found"] = True
        
        if data.get("azure", {}).get("managed_identity_token"):
            self.add_finding(
                "Azure Managed Identity Token Exposed",
                "Successfully extracted Azure managed identity token via SSRF.",
                severity="critical"
            )
            self.data["credentials_found"] = True

    def generate_report(
        self,
        output_file: str,
        target_url: str,
        severity: str = "HIGH",
        executive_summary: str = ""
    ):
        """Generate the final HTML report."""
        
        if not executive_summary:
            if self.data["credentials_found"]:
                executive_summary = (
                    "A critical Server-Side Request Forgery (SSRF) vulnerability was identified in the "
                    "LangChain application. The vulnerability allows attackers to make arbitrary HTTP "
                    "requests from the server, leading to successful extraction of cloud credentials. "
                    "This poses an immediate and severe risk to the organization's cloud infrastructure."
                )
            else:
                executive_summary = (
                    "A Server-Side Request Forgery (SSRF) vulnerability was identified in the LangChain "
                    "application (CVE-2024-12822). The vulnerability allows attackers to make arbitrary "
                    "HTTP requests from the server, potentially accessing internal services and cloud "
                    "metadata endpoints."
                )
        
        # Determine severity class
        severity_class = severity.lower()
        cvss_score = {
            "CRITICAL": "9.8",
            "HIGH": "8.6",
            "MEDIUM": "5.3"
        }.get(severity, "8.6")
        
        # Generate HTML sections
        findings_html = self.generate_findings_html()
        poc_html = self.generate_poc_html()
        
        # Fill template
        html_content = self.HTML_TEMPLATE.format(
            severity=severity,
            severity_class=severity_class,
            target_url=target_url,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cvss_score=cvss_score,
            executive_summary=executive_summary,
            findings_html=findings_html,
            poc_html=poc_html,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"✅ Report generated: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate HTML report for CVE-2024-12822 findings"
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', default='ssrf_report.html', help='Output HTML file')
    parser.add_argument('-j', '--json', help='Input JSON file with findings')
    parser.add_argument('-s', '--severity', default='HIGH', choices=['CRITICAL', 'HIGH', 'MEDIUM'],
                       help='Severity level')
    parser.add_argument('--summary', help='Custom executive summary')
    
    args = parser.parse_args()
    
    generator = SSRFReportGenerator()
    
    # Load data from JSON if provided
    if args.json:
        generator.load_from_json(args.json)
    else:
        # Add example findings for demonstration
        generator.add_finding(
            "SSRF Vulnerability Confirmed",
            "The application is vulnerable to Server-Side Request Forgery through the document loader endpoint.",
            severity="high"
        )
        
        generator.add_poc_step(
            "Step 1: Identify vulnerable endpoint",
            code='POST /api/load HTTP/1.1\nContent-Type: application/json\n\n{"url": "http://example.com"}',
            result='HTTP/1.1 200 OK\n...'
        )
    
    generator.generate_report(
        output_file=args.output,
        target_url=args.url,
        severity=args.severity,
        executive_summary=args.summary or ""
    )


if __name__ == "__main__":
    main()
