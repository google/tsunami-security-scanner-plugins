# JFrog Artifactory Authentication Bypass (CVE-2026-82329) Detector

This detector identifies JFrog Artifactory instances vulnerable to
**CVE-2026-82329**, a critical (CVSS 9.8) authentication bypass flaw in the
JFrog Access service.

## Vulnerability Details

* **CVE**: CVE-2026-82329
* **Severity**: Critical (CVSS 9.8)
* **CWE**: CWE-287 (Improper Authentication)
* **Affected Versions**:
  * 7.161.0 – 7.161.19 (Fixed in 7.161.20)
  * 7.146.0 – 7.146.36 (Fixed in 7.146.38)
  * 7.133.0 – 7.133.28 (Fixed in 7.133.29)
  * 7.125.0 – 7.125.19 (Fixed in 7.125.20)
  * 7.117.0 – 7.117.27 (Fixed in 7.117.28)
  * 7.111.4 – 7.111.21 (Fixed in 7.111.21)

### Technical Summary

Under default configurations where no additional join key is configured,
the JFrog Access component includes an empty string entry in its trusted
"join key" set. Because the signing key for a blank join key defaults to 32
bytes of `0x20` (ASCII space), an unauthenticated remote attacker can forge
a join JWT signed with this known static HMAC secret and submit it to
`/access/api/v1/registry/join`.

Upon successful join without node registration (`skip_node_registration: true`),
the Access service mints an administrative service token that can be used
directly or exchanged for a platform administrator access token.
