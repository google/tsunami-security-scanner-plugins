# Tsunami 0x0G 2024 Demo plugin
This plugin is developed to demonstrate how Tsunami can exploit RCE
vulnerability in AI Frameworks and Serving services.
In this particular case we exploit CVE-2023-48022 in RAY framework.
# Run against current CTF challenge:
java -cp "tsunami-main-0.0.23-SNAPSHOT-cli.jar:plugins/*"  com.google.tsunami.main.cli.TsunamiCli --hostname-target=chal-ray.internet-ctf.kctf.cloud --port-ranges-target=1337 --http-client-trust-all-certificates --scan-results-local-output-format=json  --scan-results-local-output-filename=/tmp/tsunami-cli.json --http-client-connect-timeout-seconds=180
