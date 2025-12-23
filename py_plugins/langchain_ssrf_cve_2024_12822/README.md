# LangChain SSRF CVE-2024-12822 Detector

This Tsunami plugin detects CVE-2024-12822, a Server-Side Request Forgery (SSRF) vulnerability in LangChain.

## Vulnerability Details

**CVE ID:** CVE-2024-12822

**Severity:** HIGH

**CWE:** CWE-918 (Server-Side Request Forgery)

**Affected Versions:** LangChain < 0.3.18

**Description:**
LangChain is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability that allows attackers to make arbitrary HTTP requests from the server. The vulnerability exists in the document loader and web retrieval components, where user-controlled URLs are not properly validated. This can lead to:

- Access to internal services and resources
- Cloud metadata endpoint exploitation (AWS, GCP, Azure)
- Port scanning of internal networks
- Potential RCE in cloud environments

**Attack Vector:**
An attacker can:
1. Submit a malicious URL through LangChain's document loader or retriever APIs
2. The server will make a request to the attacker-controlled URL
3. This can be used to access internal resources or cloud metadata endpoints
4. In cloud environments, this can escalate to credential theft and RCE

## Detection Method

This detector:
1. Identifies LangChain applications by checking for characteristic API endpoints and documentation
2. Tests common document loader endpoints with callback URLs
3. Looks for SSRF indicators in error messages (connection failures, timeouts, etc.)
4. Verifies the vulnerability by analyzing server responses

The detector tests multiple common endpoints:
- `/api/load`
- `/api/loader`
- `/api/document/load`
- `/api/retrieve`
- `/load_document`
- `/fetch_url`

## Testing

Run the unit tests:

```bash
python3 -m pytest langchain_ssrf_cve_2024_12822_test.py
```

Or with coverage:

```bash
python3 -m pytest --cov=langchain_ssrf_cve_2024_12822 langchain_ssrf_cve_2024_12822_test.py
```

## Configuration

No special configuration is required. The detector uses pattern matching to identify SSRF behavior.

## Remediation

- **Upgrade** to LangChain version 0.3.18 or later
- **Implement URL allowlisting** for all document loaders and web retrievers
- **Validate and sanitize** all user-provided URLs
- **Use network segmentation** to restrict server-side requests
- **Block access** to cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
- **Implement** rate limiting on document loading endpoints
- **Monitor** for unusual outbound connection patterns

## Impact in Cloud Environments

In AWS, GCP, or Azure environments, this SSRF can be particularly dangerous:

```bash
# Example SSRF to AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# This can lead to:
- AWS credential theft
- Role assumption
- Full account compromise
```

## References

- [CVE-2024-12822](https://nvd.nist.gov/vuln/detail/CVE-2024-12822)
- [LangChain GitHub Repository](https://github.com/langchain-ai/langchain)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## Author

Tsunami Community Contributor

## License

Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
