# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) RCE Detector

## Description
This plugin detects instances of PHP vulnerable to **PHP2Shell**
(CVE-2026-109618 and CVE-2026-109619). The vulnerability allows unauthenticated
remote attackers to achieve Remote Code Execution (RCE) by abusing
out-of-memory error-handling bailout corruption combined with stale global
state tracking in `session.upload_progress`.

## Target
Any web service running PHP versions 5.4 through 8.5.11 prior to emergency
patches.

## Verification
Active verification is performed using Tsunami's `PayloadGenerator` with the
Tsunami Callback Server (TCS).
