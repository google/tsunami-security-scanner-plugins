# Flowise RCE CVE-2025-58434 Detector

This Tsunami plugin detects CVE-2025-58434, a critical remote code execution vulnerability in Flowise.

## Vulnerability Details

**CVE ID:** CVE-2025-58434

**Severity:** CRITICAL

**Affected Versions:** Flowise < 2.2.0

**Description:**
Flowise is vulnerable to a critical remote code execution vulnerability in the tool execution flow. An attacker can exploit this by crafting a malicious chatflow that executes arbitrary code on the server through the Custom Tool functionality. The vulnerability exists due to insufficient input validation in the custom tool code execution path.

**Attack Vector:**
An attacker can:
1. Access the Flowise API (often exposed without authentication)
2. Create a malicious chatflow with embedded code in the Custom Tool configuration
3. Trigger the chatflow to execute arbitrary commands on the server

## Detection Method

This detector:
1. Identifies Flowise instances by querying the `/api/v1/chatflows` endpoint
2. Creates a test chatflow with a payload that triggers a callback to the Tsunami callback server
3. Executes the chatflow to trigger the RCE
4. Verifies exploitation by checking if the callback was received
5. Cleans up by deleting the test chatflow

## Testing

Run the unit tests:

```bash
python3 -m pytest flowise_rce_cve_2025_58434_test.py
```

Or with coverage:

```bash
python3 -m pytest --cov=flowise_rce_cve_2025_58434 flowise_rce_cve_2025_58434_test.py
```

## Configuration

No special configuration is required. The detector uses the Tsunami payload generator framework for RCE verification.

## Remediation

- **Upgrade** to Flowise version 2.2.0 or later
- **Validate** and sanitize all user inputs, especially in custom tool configurations
- **Restrict** access to the Flowise API
- **Implement** strong authentication and authorization mechanisms
- **Monitor** for suspicious chatflow creation or execution patterns

## References

- [CVE-2025-58434](https://nvd.nist.gov/vuln/detail/CVE-2025-58434)
- [Flowise GitHub Repository](https://github.com/FlowiseAI/Flowise)
- [Flowise Security Advisory](https://github.com/FlowiseAI/Flowise/security/advisories)

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
