# Cloud, Vulnerability, and Credential Reconnaissance Tooling

This reference collects the exhaustive command catalogs extracted from the
`performing-reconnaissance` skill. It covers cloud storage asset discovery,
automated and targeted vulnerability scanning, and credential-gathering
sources. Use it alongside the core methodology in `../SKILL.md`.

## Contents

- [Cloud Asset Discovery](#6-cloud-asset-discovery)
  - [AWS S3 Buckets](#aws-s3-buckets)
  - [Azure Blobs](#azure-blobs)
  - [Google Cloud Storage](#google-cloud-storage)
- [Vulnerability Scanning](#7-vulnerability-scanning)
  - [Automated Scanners](#automated-scanners)
  - [Specific Vulnerability Checks](#specific-vulnerability-checks)
- [Credential Gathering](#8-credential-gathering)
  - [Default Credentials](#default-credentials)
  - [Public Repositories](#public-repositories)
  - [Metadata Extraction](#metadata-extraction)

### 6. Cloud Asset Discovery

**AWS S3 Buckets:**
```bash
# Check for public buckets
# Format: bucketname.s3.amazonaws.com
curl -I https://company.s3.amazonaws.com

# Bucket name wordlist
# company-backup, company-data, company-dev, etc.

# Tools
# s3scanner
python3 s3scanner.py buckets.txt

# awscli
aws s3 ls s3://bucketname --no-sign-request
```

**Azure Blobs:**
```bash
# Format: accountname.blob.core.windows.net
curl -I https://company.blob.core.windows.net/container

# MicroBurst (PowerShell)
Invoke-EnumerateAzureBlobs -Base company
```

**Google Cloud Storage:**
```bash
# Format: storage.googleapis.com/bucketname
curl -I https://storage.googleapis.com/company-bucket

# GCPBucketBrute
python3 gcpbucketbrute.py -k company
```

### 7. Vulnerability Scanning

**Automated Scanners:**
```bash
# Nikto (web vulnerabilities)
nikto -h https://target.com

# Nuclei (template-based)
nuclei -u https://target.com -t ~/nuclei-templates/

# OpenVAS (comprehensive)
# Use GUI or command line

# Nessus (commercial)
# Web-based scanner
```

**Specific Vulnerability Checks:**
```bash
# SSL/TLS
nmap -p 443 --script ssl-* target.com
testssl.sh https://target.com

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch

# XSS
dalfox url https://target.com/search?q=test

# SSRF
# Manual testing or use Burp Suite

# Directory traversal
# Test: ../../../../etc/passwd
```

### 8. Credential Gathering

**Default Credentials:**
```bash
# Check default credentials databases
# - CIRT.net default passwords
# - DefaultCreds-cheat-sheet
# - SecLists default credentials

# Common defaults
admin:admin
admin:password
root:root
admin:Admin123
```

**Public Repositories:**
```bash
# GitHub secrets scanning
trufflehog https://github.com/company/repo

# GitLeaks
gitleaks detect --source /path/to/repo

# GitHub dorks
filename:.env "DB_PASSWORD"
extension:pem private
extension:sql mysql dump password
```

**Metadata Extraction:**
```bash
# exiftool
exiftool document.pdf
find . -name "*.pdf" -exec exiftool {} \;

# FOCA (Windows)
# Extract metadata from documents
```
