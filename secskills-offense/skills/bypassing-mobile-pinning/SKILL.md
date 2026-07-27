---
name: bypassing-mobile-pinning
description: Diagnose and defeat TLS interception failures in mobile apps — certificate pinning, Android Network Security Config, user-CA distrust, native BoringSSL pinning, and mutual TLS — using objection, Frida, SSL Kill Switch, and APK patching. Use when Burp, mitmproxy, or Charles shows a TLS handshake error, an empty proxy, or "network error" from a mobile app, or when a target is known to pin certificates.
verified: 2026-07-27
---

# Bypassing Mobile Pinning

Most time lost here is spent bypassing pinning that was never there. An empty
proxy has at least six causes, and the fix for each is different — one of them
is not pinning at all but Android's default distrust of user CAs, and another
is that the app has its own TLS stack and never saw your proxy. Diagnose
before you reach for a bypass script.

Use only against apps you are authorized to test.

## When to Use

- Burp/mitmproxy/Charles shows a TLS handshake failure from a mobile app
- The proxy shows nothing while the app clearly reaches the network
- The app reports "network error", "connection insecure", or similar with the
  proxy configured
- You know the target pins, and need the right hook for its stack

## When NOT to Use

- **Flutter targets** — use `reversing-flutter-apps`; Flutter's failure looks
  identical but the cause and fix are specific to its engine
- **The wider mobile assessment** — use `testing-mobile-applications`
- **The backend once traffic is visible** — use `testing-apis`
- **Reversing a native `.so` in depth** — use `analyzing-binaries`

## Diagnose First

Run this before installing anything. The symptom tells you the cause.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Proxy sees the CONNECT, then TLS alert `unknown_ca` / `bad_certificate` | Your CA is not trusted | Install as **system** CA, or patch Network Security Config |
| Proxy sees the CONNECT, then alert only for *some* domains | Real pinning, scoped to those hosts | Hook the pinning check |
| Proxy sees **nothing at all**, app works | App ignores the system proxy | Force traffic at the network layer (Flutter, gRPC, some SDKs) |
| Proxy sees the handshake, server rejects the client | Mutual TLS — the app presents a client certificate | Extract the client cert; this is not pinning |
| Works on emulator, fails on device (or vice versa) | Root/emulator detection, not TLS | Different problem — see the detection section |
| Fails only after login | Pinning applied to the API host only | Hook, then re-check |

```bash
# What does the app actually declare?
apktool d target.apk -o out
cat out/res/xml/network_security_config.xml 2>/dev/null
rg -n 'networkSecurityConfig|usesCleartextTraffic' out/AndroidManifest.xml

# Which TLS stack is in play?
rg -l 'okhttp3|CertificatePinner|TrustKit|AFNetworking|Alamofire' out/ 2>/dev/null | head
unzip -l target.apk | rg 'libssl|libcrypto|libconscrypt|libflutter|libil2cpp|libmonodroid'
```

**Check Network Security Config before assuming pinning.** Since Android 7,
apps do not trust user-installed CAs by default. An app with no pinning code
at all will still fail interception. Two fixes:

```bash
# A. Install your CA as a SYSTEM certificate (no app modification — preferred)
#    Emulator:
emulator -avd <name> -writable-system
adb root && adb remount
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1   # → e.g. 9a5ba580
cp burp.pem 9a5ba580.0 && adb push 9a5ba580.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba580.0
#    Rooted device: use a Magisk module so the change survives reboot

# B. Patch the config and repack (when you cannot get a system CA)
#    Add to network_security_config.xml:
#      <base-config><trust-anchors>
#        <certificates src="system"/><certificates src="user"/>
#      </trust-anchors></base-config>
apktool b out -o patched.apk && apksigner sign --ks debug.keystore patched.apk
```

Option A is better: it modifies nothing in the app, so integrity checks,
signature checks, and Play Integrity are unaffected. Reach for B only when you
cannot get a system CA onto the device.

## Android: Hook by Stack

Identify the stack, then hook it. A generic script that misses will look like
"the bypass failed" when it simply targeted the wrong layer.

```bash
# Start here — covers the common Java-layer stacks in one shot
objection -g com.target.app explore
# then: android sslpinning disable

# Or a maintained universal script
frida -U -f com.target.app -l android-ssl-bypass.js --no-pause
```

| Stack | Marker | Hook point |
| --- | --- | --- |
| OkHttp 3/4 | `okhttp3.CertificatePinner` | `CertificatePinner.check()` — return normally |
| HttpURLConnection | `javax.net.ssl.*` | Custom `X509TrustManager.checkServerTrusted()` |
| Conscrypt | `libconscrypt_jni.so` | `Platform.checkServerTrusted`, or the native layer |
| Apache HttpClient | `org.apache.http` | `SSLSocketFactory` verifier |
| WebView | `onReceivedSslError` | Force `handler.proceed()` |
| **Native / BoringSSL** | `libssl.so`, custom `.so` | `SSL_CTX_set_custom_verify`, `ssl_verify_peer_cert` |
| Xamarin | `libmonodroid.so`, `libxamarin*` | Mono-level `ServicePointManager` / `HttpClientHandler` |
| Unity | `libil2cpp.so` | `UnityWebRequest` cert handler, or BestHTTP's verifier |
| gRPC | `libgrpc.so` | Channel credentials; often also ignores the proxy |

**Native pinning is where the universal scripts stop working.** When
`objection` reports success but traffic still fails, the check is in a `.so`.
BoringSSL's verification entry points are not exported, so scripts locate them
by pattern scanning — and the pattern is version-specific. Confirm what you
are dealing with:

```bash
# Is a native TLS stack even present?
unzip -j target.apk 'lib/arm64-v8a/*' -d libs && rg -l 'SSL_|BoringSSL|s2n' libs/
# Trace the native calls to see which library terminates TLS
frida-trace -U -f com.target.app -i 'SSL_*' -i '*verify*'
```

For Unity, Xamarin, and Flutter builds, recover symbols first —
`reversing-unity-il2cpp`, `reversing-flutter-apps` — then hook the named
function rather than pattern-scanning blind.

## iOS

```bash
# Frida-based, covers NSURLSession and the common libraries
objection -g com.target.app explore
# then: ios sslpinning disable

# Jailbroken device, no Frida
# SSL Kill Switch 3 — system-wide, survives app updates
```

| Library | Hook point |
| --- | --- |
| NSURLSession (default) | `URLSession:didReceiveChallenge:` → `.useCredential` with the server trust |
| TrustKit | `TSKPinningValidator` result |
| AFNetworking | `AFSecurityPolicy.evaluateServerTrust:` |
| Alamofire | `ServerTrustManager` / `ServerTrustEvaluating` |
| Native/BoringSSL | Same as Android — hook the verify callback |

Non-jailbroken devices: repackage the IPA with the Frida gadget
(`objection patchipa`), re-sign, and sideload. Expect this to trip integrity
or attestation checks in hardened apps.

## When It Still Fails

Work through these in order rather than trying more bypass scripts.

1. **The app never used your proxy.** Some stacks ignore system proxy settings
   entirely. Force traffic: transparent redirect with `iptables`, or a
   VPN/tun-based proxy.
   ```bash
   adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <proxy>:8080'
   ```
2. **Certificate Transparency enforcement.** Some SDKs require SCTs; your CA
   has none. Look for CT libraries and hook the CT verifier specifically.
3. **Mutual TLS.** The server demands a client certificate. Extract the `.p12`
   or keystore from the app bundle, recover its password (often in code or
   `strings`), and load it into your proxy's client-certificate settings. This
   is a separate mechanism from pinning and no pinning bypass will touch it.
4. **Root/jailbreak or Frida detection.** The app detects instrumentation and
   fails closed, which looks like a TLS problem. Check for a `frida` string
   scan, port 27042 probing, `/proc/self/maps` inspection, or Play Integrity.
   Bypass the detection first, then retry the pinning bypass.
5. **The traffic is not HTTP.** WebSockets, gRPC, MQTT, or a custom protocol
   over TLS. Your HTTP proxy will not show it — capture at the socket layer or
   with a protocol-aware proxy.
6. **Pinning applied only to specific hosts.** Analytics flows fine while the
   API fails. Confirm by comparing which hosts appear in the proxy.

## Verify You Actually Won

A bypass is confirmed when you can see and *modify* a request end to end —
not when the app merely stops erroring.

```
1. Proxy shows the API host, not just analytics and CDN traffic
2. Request and response bodies are readable
3. A modified request produces a different server response
4. Authenticated flows still work through the proxy
```

If only step 1 passes, you may be seeing a fallback path while the real API
traffic goes elsewhere.

## Rationalizations to Reject

- *"The bypass failed, the app must use strong pinning."* Six causes, one of
  which is pinning. Diagnose from the symptom table.
- *"I installed the CA, so TLS should work."* As a *user* certificate, on
  Android 7+, for an app that does not opt in — it will not.
- *"objection said pinning disabled."* It disabled the Java-layer checks it
  knows. Native pinning is untouched.
- *"No traffic in the proxy means the app is offline."* It means the app is not
  using your proxy.
- *"I'll just patch the APK."* Repacking breaks signatures and trips integrity
  checks. Prefer a system CA and runtime hooks; patch as a last resort.
- *"Pinning bypassed, assessment done."* Bypassing pinning is setup, not a
  finding. Pinning is a defense-in-depth control, and its absence is a low
  severity note — the findings are in the API behind it.

## References

- `testing-mobile-applications` — the wider assessment this unblocks
- `reversing-flutter-apps` — Flutter's separate TLS stack and proxy behaviour
- `reversing-unity-il2cpp`, `reversing-react-native-apps` — symbol recovery
  before hooking framework-specific stacks
- `testing-apis` — where the actual findings are, once you can see the traffic
- objection, Frida, SSL Kill Switch 3, apktool, apksigner, Magisk
