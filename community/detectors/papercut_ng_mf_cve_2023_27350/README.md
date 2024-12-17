# Papercut NG/MF Authentication Bypass and RCE Detector

### CVE

[CVE-2023-27350](https://github.com/advisories/GHSA-cfg6-7x4x-p3pj)

### Description of Vulnerability

Allows remote attackers to bypass authentication on affected installations of
PaperCut NG/MF. Authentication is not required to exploit this vulnerability.
The specific flaw exists within the SetupCompleted class and the issue results
from improper access control An attacker can leverage this vulnerability to
bypass authentication and execute arbitrary code in the context of SYSTEM
(Windows) or Root/Papercut User (Linux).

Application allows for Remote Code Execution on the webserver. The RCE can be
used to directly execute commands on the remote Papercut Webserver, or a
malicious JAR file can be dropped/executed.

##### Related Articles:

https://vulncheck.com/blog/papercut-rce
https://www.bleepingcomputer.com/news/security/new-papercut-rce-exploit-created-that-bypasses-existing-detections/
https://thehackernews.com/2023/05/researchers-uncover-new-exploit-for.html

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

--------------------------------------------------------------------------------

## Testing

Images and OCI image sources to test this plugin can be found at:
https://github.com/Isaac-GC/papercut_ng_mf_docker_images

These images simulate a near realistic production environment and are
prebuilt/preconfigured to let you get started ASAP. They currently consist of
two version types: - Vulnerable -
`ghcr.io/isaac-gc/papercut_ng_mf:19.2.7.62195` -
`ghcr.io/isaac-gc/papercut_ng_mf:20.1.4.57927` -
`ghcr.io/isaac-gc/papercut_ng_mf:21.2.10.62186` -
`ghcr.io/isaac-gc/papercut_ng_mf:22.0.1.62695`

-   Non-vulnerable (patched)
    -   `ghcr.io/isaac-gc/papercut_ng_mf:20.1.8.66704`
    -   `ghcr.io/isaac-gc/papercut_ng_mf:21.2.12.66701`
    -   `ghcr.io/isaac-gc/papercut_ng_mf:22.0.12.66453`

#### Using the images

1.  Pull down an OCI image for the version you want to use/test.
    -   i.e. `docker pull ghcr.io/isaac-gc/papercut_ng_mf:22.0.1.62695`
2.  Run the container using docker, kubernetes, or another OCI compatible engine
    -   I.e. using docker: `docker run -it --rm -p 9191:9191
        ghcr.io/isaac-gc/papercut_ng_mf:22.0.1.62695`
3.  Thats it
