---
name: testing-mobile-applications
description: Pentest Android and iOS mobile applications including APK analysis, dynamic analysis, SSL pinning bypass, root/jailbreak detection bypass, and mobile-specific vulnerabilities. Use when testing mobile app security or performing mobile pentesting.
---

# Testing Mobile Applications

## When to Use

- Android APK analysis and exploitation
- iOS application pentesting
- Mobile app security assessment
- Bypassing security controls (SSL pinning, root detection)
- Testing mobile-specific vulnerabilities

## Android Pentesting

### APK Analysis Tools

```bash
# Decompile APK
apktool d app.apk -o app_decompiled

# Convert DEX to JAR
d2j-dex2jar app.apk

# View JAR with JD-GUI
jd-gui app-dex2jar.jar

# Automated analysis
mobsf  # Mobile Security Framework
jadx app.apk  # APK to Java decompiler
```

### ADB (Android Debug Bridge)

```bash
# List devices
adb devices

# Connect over network
adb connect 192.168.1.100:5555

# Install APK
adb install app.apk

# Uninstall
adb uninstall com.package.name

# List packages
adb shell pm list packages
adb shell pm list packages | grep -i "keyword"

# Get APK path
adb shell pm path com.package.name

# Pull APK from device
adb pull /data/app/com.package.name-xxx/base.apk

# Start activity
adb shell am start -n com.package.name/.MainActivity

# View logs
adb logcat

# Shell access
adb shell
```

### Static Analysis

**Search for Sensitive Data:**
```bash
# Extract strings
strings app.apk | grep -i password
strings app.apk | grep -i api
strings app.apk | grep -i token
strings app.apk | grep -i key

# Search in decompiled code
grep -r "password" app_decompiled/
grep -r "http://" app_decompiled/
grep -r "api_key" app_decompiled/
```

**Check AndroidManifest.xml:**
```bash
# Decompile and view
apktool d app.apk
cat app_decompiled/AndroidManifest.xml

# Look for:
# - android:debuggable="true"
# - android:allowBackup="true"
# - Exported activities/services
# - Custom permissions
# - URL schemes
```

### Dynamic Analysis

**Frida (Runtime Instrumentation):**
```bash
# List running apps
frida-ps -U

# Attach to app
frida -U -n "App Name"
frida -U -f com.package.name

# Load script
frida -U -f com.package.name -l script.js

# Common scripts
# - Bypass SSL pinning
# - Bypass root detection
# - Hook functions
# - Dump memory
```

**SSL Pinning Bypass:**
```javascript
// Frida script - Universal SSL pinning bypass
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    TrustManager.checkServerTrusted.implementation = function() {};

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(a,b,c) {
        this.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').call(this, a, null, c);
    };
});
```

**Root Detection Bypass:**
```javascript
// Frida - Bypass root detection
Java.perform(function() {
    var RootClass = Java.use('com.package.name.RootDetection');
    RootClass.isRooted.implementation = function() {
        return false;
    };
});
```

### Intercepting Traffic

**Burp Suite Setup:**
```bash
# 1. Install Burp CA certificate
# Download from http://burp:8080 on device
# Install in Settings -> Security -> Install from storage

# 2. Configure proxy
adb shell settings put global http_proxy 192.168.1.100:8080

# 3. For apps with SSL pinning, use Frida bypass

# 4. Clear proxy when done
adb shell settings put global http_proxy :0
```

**mitmproxy:**
```bash
# Start mitmproxy
mitmproxy --listen-port 8080

# Install certificate on device
# http://mitm.it

# Set device proxy to attacker IP:8080
```

### Modifying and Repackaging APK

```bash
# 1. Decompile
apktool d app.apk -o app_mod

# 2. Modify smali code
# Edit files in app_mod/smali/

# 3. Recompile
apktool b app_mod -o app_modified.apk

# 4. Sign APK
# Generate keystore (first time only)
keytool -genkey -v -keystore my-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

# Sign
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key.keystore app_modified.apk alias_name

# Or use uber-apk-signer
java -jar uber-apk-signer.jar -a app_modified.apk

# 5. Install
adb install app_modified.apk
```

### Common Vulnerabilities

**Insecure Data Storage:**
```bash
# Check shared preferences
adb shell
cd /data/data/com.package.name/shared_prefs/
cat *.xml

# Check databases
cd /data/data/com.package.name/databases/
sqlite3 database.db
.tables
SELECT * FROM users;

# Check files
cd /data/data/com.package.name/files/
ls -la
cat *
```

**Exported Components:**
```bash
# List exported activities
adb shell dumpsys package com.package.name | grep -A 20 "Activity"

# Start exported activity
adb shell am start -n com.package.name/.ExportedActivity

# Call exported service
adb shell am startservice -n com.package.name/.ExportedService

# Broadcast to receiver
adb shell am broadcast -a com.package.name.ACTION
```

**Insecure WebView:**
```bash
# Check for JavaScript enabled
# Look in code for:
webView.getSettings().setJavaScriptEnabled(true);

# Check for addJavascriptInterface
# Can lead to RCE if exposed
```

## iOS Pentesting

### Setup

**Jailbreak Tools:**
- checkra1n (iOS 12-14)
- unc0ver (iOS 11-14.8)
- Taurine (iOS 14-14.3)

**SSH Access:**
```bash
# Default credentials
ssh root@<device-ip>
# password: alpine

# Change default password!
passwd
```

### IPA Analysis

```bash
# Extract IPA
unzip app.ipa

# View binary
otool -L Payload/App.app/App
strings Payload/App.app/App

# Class dump
class-dump Payload/App.app/App > classes.txt

# Decrypt binary (on jailbroken device)
frida-ios-dump -u App

# Static analysis with Hopper/Ghidra
```

### Runtime Analysis

**Frida on iOS:**
```bash
# List apps
frida-ps -Ua

# Attach
frida -U -n "App Name"
frida -U -f com.company.app

# SSL pinning bypass (iOS)
objection -g "App Name" explore
ios sslpinning disable
```

**Objection:**
```bash
# Launch objection
objection -g com.company.app explore

# Common commands
ios info binary
ios hooking list classes
ios hooking search methods MainActivity
ios sslpinning disable
ios jailbreak disable
ios keychain dump
ios nsuserdefaults get
```

### File System Access

```bash
# Connect via SSH
ssh root@device-ip

# App data location
cd /var/mobile/Containers/Data/Application/<UUID>/

# Find app UUID
ipainstaller -l  # List apps
ls /var/mobile/Containers/Data/Application/

# Common paths
Documents/
Library/
Library/Preferences/  # plist files
Library/Caches/
tmp/
```

### Keychain Access

```bash
# Using objection
ios keychain dump

# Manual (requires keychain-dumper on device)
./keychain_dumper

# Specific item
security find-generic-password -s "ServiceName"
```

### Common iOS Vulnerabilities

**Insecure Data Storage:**
```bash
# Check plist files
plutil -p Info.plist

# Check UserDefaults
ios nsuserdefaults get

# Check SQLite databases
sqlite3 database.db
.tables
SELECT * FROM sensitive_table;
```

**Binary Protections:**
```bash
# Check for PIE
otool -hv App | grep PIE

# Check for stack canaries
otool -I App | grep stack_chk

# Check for ARC
otool -I App | grep objc_release
```

## Mobile-Specific Attacks

**Deep Link Exploitation:**
```bash
# Android
adb shell am start -a android.intent.action.VIEW -d "app://open?param=value"

# iOS
xcrun simctl openurl booted "app://open?param=value"
```

**Intent Injection:**
```bash
# Send malicious intent
adb shell am start -n com.package/.Activity --es "extra_key" "malicious_value"
```

**Backup Extraction:**
```bash
# Android backup
adb backup -f backup.ab com.package.name
# Extract
java -jar abe.jar unpack backup.ab backup.tar

# iOS backup
idevicebackup2 backup --full backup_directory
```

## Tools

**Android:**
- APKTool - Decompile/recompile APKs
- dex2jar - Convert DEX to JAR
- JADX - APK to Java decompiler
- Frida - Dynamic instrumentation
- Objection - Frida-based toolkit
- MobSF - Automated analysis
- Drozer - Android security framework

**iOS:**
- Frida - Dynamic instrumentation
- Objection - Frida toolkit
- class-dump - Extract class info
- Hopper/Ghidra - Disassemblers
- frida-ios-dump - Decrypt binaries
- iproxy - Forward ports

## Quick Testing Workflow

1. **Static Analysis** - Decompile, search strings, analyze manifest/Info.plist
2. **Install** - Install on emulator/device
3. **Intercept Traffic** - Set up Burp/mitmproxy, bypass SSL pinning
4. **Dynamic Analysis** - Use Frida to hook functions, bypass protections
5. **Test Components** - Test exported components, deep links, intents
6. **Data Storage** - Check for insecure data storage in files/DB/keychain
7. **Repackage** - Modify and recompile to test additional scenarios

## References

- https://book.hacktricks.xyz/mobile-pentesting
- https://github.com/OWASP/owasp-mstg
- https://mobile-security.gitbook.io/
