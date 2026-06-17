

# 🎯 Detect LINE VIPER WebVPN Command and Control on Cisco ASA

**🚩 Priority : `Critical`**

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.

🗡️ **ATT&CK Techniques** :  [T1071.001 : Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detectionnetwork filtering by blending in with exis'), [T1573.001 : Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001 'Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections p'), [T1573.002 : Encrypted Channel: Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002 'Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections '), [T1090 : Proxy](https://attack.mitre.org/techniques/T1090 'Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and'), [T1542.003 : Pre-OS Boot: Bootkit](https://attack.mitre.org/techniques/T1542/003 'Adversaries may use bootkits to persist on systems A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious c'), [T1601.001 : Modify System Image: Patch System Image](https://attack.mitre.org/techniques/T1601/001 'Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defensesCitation Killing the myth of ')

---

`🔑 UUID : 8546b0d8-c9e1-4a51-bf64-2b93c4159ebf` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2026-06-18` **|** `🗓️ Last Modification : 2026-06-18` **|** `👩‍💻 Model author : None` **|** `👥 Contributors : None` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : dom::1.0`

## 💡 Objective

**🏷️ Type** : Threat - Alerts meant for detection cybersecurity threats, and which should eventually trigger Incident Response  

> This detection objective targets the WebVPN-based command and control
> channel used by the LINE VIPER implant on compromised Cisco ASA
> devices. LINE VIPER abuses legitimate WebVPN client authentication
> endpoints to deliver tasking payloads and receive exfiltrated data,
> blending malicious traffic with expected VPN authentication flows.
> 
> The initial LINE VIPER shellcode delivery also exploits this same
> WebVPN authentication mechanism: a crafted authentication request
> embedding a partial PKCS7 certificate followed by shellcode triggers
> the handler installed by the RayInitiator bootkit in the lina binary.
> 
> Detection is particularly challenging because the C2 channel uses
> standard HTTPS on port 443 with valid WebVPN endpoint paths and
> plausible XML request structures. Detection requires deep inspection
> of WebVPN authentication traffic patterns, certificate artefact
> analysis, and behavioural anomaly detection on the ASA device.
> 
> Detection investment is Major given the requirement for HTTPS
> inspection capabilities, Cisco ASA syslog telemetry at the required
> fidelity, and the need for network forensics tooling to analyse
> encrypted traffic patterns against baseline WebVPN behaviour.
> 

**🎼 Composition** : Combined - All signals triggered for any entity can be grouped in a single signal. This may be extremely useful to identify pan-environment compromises.

> Detection strategy combines network-based inspection of WebVPN
authentication requests with host-based behavioural anomalies
observable via Cisco ASA syslog telemetry.

Primary approach focuses on three complementary angles:

1. **Certificate Artefact Detection**: WebVPN authentication
   requests from LINE VIPER include a partial PKCS7 certificate
   followed by shellcode. Network inspection should identify
   authentication requests where the certificate field is
   malformed, truncated, or does not constitute a valid X.509
   certificate chain. The presence of executable-like byte
   sequences following the certificate boundary is a strong
   indicator.

2. **XML Payload Anomaly Detection**: Tasking requests embed
   operator commands within device-type or related XML form
   elements. Baseline WebVPN authentication traffic carries
   short, predictable values in these fields. Statistically
   anomalous field lengths, encoding patterns, or encrypted
   blobs in these positions warrant investigation.

3. **Response Pattern Analysis**: LINE VIPER responses to WebVPN
   C2 queries return data embedded in the `message` XML element,
   which is atypical for legitimate authentication denials or
   success responses. Detection of non-standard content in WebVPN
   XML response message elements from the ASA device provides
   high-fidelity signal.

Signals should be correlated per source IP and per device to
distinguish individual attacker sessions from background noise.
Correlation with ICMP/TCP anomalies (see companion DOM) increases
confidence.


### 🌊 Related OpenTide Objects


```mermaid

mindmap
Root[🎯 Detect LINE VIPER WebVPN Command and Control on Cisco ASA]
    
      📡 Malformed PKCS7 Certificate in WebVPN Authentication Request 
      📡 Anomalous XML Payload in WebVPN Authentication Form Elements 
      📡 NonStandard Content in Cisco ASA WebVPN Authentication Response 
      ☣️ WebVPN authentication abuse for C2 on Cisco ASA 
      ☣️ LINE VIPER shellcode loader on Cisco ASA 


```


**Threats**

| ☣️ Threat Vectors (2)                                                                                                                                                                                                                                                                                 |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [LINE VIPER shellcode loader on Cisco ASA](../Threat%20Vectors/☣️%20LINE%20VIPER%20shellcode%20loader%20on%20Cisco%20ASA 'LINE VIPER is a sophisticated user-mode shellcode loader withassociated modules that targets Cisco ASA Adaptive SecurityAppliance devices It represent...')                 |
| [WebVPN authentication abuse for C2 on Cisco ASA](../Threat%20Vectors/☣️%20WebVPN%20authentication%20abuse%20for%20C2%20on%20Cisco%20ASA 'LINE VIPER implements a sophisticated command and control mechanismthat abuses legitimate WebVPN client authentication functionality onCisco ASA devic...') |

**Rules**

| 📡 Detection Objective Signals (3)                                                                                                                                                                                                                                                                 | 🚨 Detection Rules    |
|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|
| [Malformed PKCS7 Certificate in WebVPN Authentication Request](#malformed-pkcs7-certificate-in-webvpn-authentication-request 'Detects WebVPN client authentication requests to a Cisco ASAdevice where the certificate field contains a malformed orpartial PKCS7 structure, consist...')         | ❌ No Detection Rules |
| [Non-Standard Content in Cisco ASA WebVPN Authentication Response](#non-standard-content-in-cisco-asa-webvpn-authentication-response 'Detects Cisco ASA WebVPN authentication responses that embeddata in the XML message element in a manner inconsistent withlegitimate authentication out...') | ❌ No Detection Rules |
| [Anomalous XML Payload in WebVPN Authentication Form Elements](#anomalous-xml-payload-in-webvpn-authentication-form-elements 'Detects WebVPN authentication requests where standard XML formelements carry anomalously large, encoded, or encrypted payloadsinconsistent with legiti...')         | ❌ No Detection Rules |

## 📡 Signals


### Malformed PKCS7 Certificate in WebVPN Authentication Request

🪪 **UUID** : `22e8fb52-d101-4d67-90b7-6e697c2dbb2d`

> Detects WebVPN client authentication requests to a Cisco ASA
device where the certificate field contains a malformed or
partial PKCS7 structure, consistent with the LINE VIPER initial
shellcode delivery mechanism [1].

LINE VIPER is loaded via a crafted authentication request that
embeds a partial PKCS7 certificate immediately followed by
shellcode. A valid PKCS7/CMS structure has well-defined ASN.1
DER boundaries; a partial or truncated structure followed by
non-DER bytes is structurally invalid.

Detection approach:
- Monitor HTTPS POST requests to Cisco ASA WebVPN endpoints
  (typically `/+webvpn+/index.html`, `/CACHE/`, or equivalent
  authentication paths)
- Inspect the body for `config-auth` XML elements containing
  certificate data in forms fields
- Flag certificate fields that begin with a valid PKCS7/CMS
  DER header (0x30 0x82 or 0x30 0x80) but are truncated or
  followed by non-DER byte sequences
- Alert on WebVPN auth requests where certificate payload size
  is anomalously large (shellcode appended after partial cert)

This signal requires TLS inspection or out-of-band network
visibility (e.g., mirrored traffic, firewall deep inspection).


**🔎 Data Visibility**

- **Availability** : Partial
- **Requirements** : `- HTTPS/TLS inspection or mirrored network traffic to Cisco
  ASA WebVPN interface
- Network-level packet capture or inline inspection capability
  with certificate field parsing
- Firewall or proxy logs with request body inspection enabled

Preferred log sources:
- NGFW/IDS with SSL inspection (Cisco FTD, Palo Alto, etc.)
- Network TAP or SPAN port capture feeding Suricata/Zeek
- Cisco ASA firewall logs with extended logging enabled
`

_💾 Possible logsources_

_❌ No logsources mentioned_

**🧲 Related Entities**

| Name               | Category                                        | Description                                                                                                                                                                                  |
|:-------------------|:------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IP Address         | **Network Entities** : Network Related Entities | Represents an IPv4 or IPv6 address associated with a host or networkconnection.                                                                                                              |
| URL                | **Network Entities** : Network Related Entities | Represents a Uniform Resource Locator (URL), often used in web-basedattacks or phishing campaigns.                                                                                           |
| Certificate        | **Network Entities** : Network Related Entities | Represents a digital certificate, including its issuer, validity, and usage. Certificates are often analyzed to detect spoofing or expired credentials.                                      |
| Network Connection | **Network Entities** : Network Related Entities | Represents a network connection, including source and destination IPs, ports, and protocols. This entity is critical for detecting suspicious or unauthorized communication between systems. |

**⚠️ Detectors**

_❌ No detectors mentioned_

**🌐 Examples**

_❌ No examples mentioned_



### Anomalous XML Payload in WebVPN Authentication Form Elements

🪪 **UUID** : `cff09577-eb0b-4ac9-9393-789dbe439b56`

> Detects WebVPN authentication requests where standard XML form
elements carry anomalously large, encoded, or encrypted payloads
inconsistent with legitimate VPN client authentication [1].

LINE VIPER embeds operator tasking data within device-type or
similar XML form fields of the WebVPN authentication request.
Legitimate WebVPN clients send short, predictable values in
these fields (e.g., device type strings of 5-30 characters).
Attacker-controlled requests embed base64-encoded or encrypted
blobs of significantly larger size.

Detection criteria:
- WebVPN XML `config-auth` requests where `device-type`,
  `platform`, or `opaque` elements exceed a defined size
  threshold (e.g., >512 bytes) or contain high-entropy content
- Requests with `aggregate-auth-version="2"` header but
  device-type field values that do not match known VPN client
  vendor strings
- Repeated WebVPN authentication attempts from the same source
  IP with varying large payloads in form fields (C2 tasking
  sessions)
- Authentication requests with Content-Type set to
  `application/x-www-form-urlencoded` but body conforming to
  XML rather than URL-encoded format

Baseline of legitimate WebVPN authentication traffic is required
to tune thresholds and reduce false positives from non-standard
VPN clients.


**🔎 Data Visibility**

- **Availability** : Partial
- **Requirements** : `- HTTPS inspection with WebVPN request body parsing
- Cisco ASA WebVPN authentication logs (syslog facility)
- Baseline of legitimate WebVPN authentication traffic patterns
- Ability to inspect XML body content of HTTPS POST requests

Preferred log sources:
- Cisco ASA syslog (authentication events, WebVPN session logs)
- NGFW with application layer inspection for WebVPN traffic
- Zeek HTTP/TLS logs with body extraction enabled
- Intrusion Detection System with custom WebVPN signatures
`

_💾 Possible logsources_

_❌ No logsources mentioned_

**🧲 Related Entities**

| Name               | Category                                        | Description                                                                                                                                                                                      |
|:-------------------|:------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IP Address         | **Network Entities** : Network Related Entities | Represents an IPv4 or IPv6 address associated with a host or networkconnection.                                                                                                                  |
| URL                | **Network Entities** : Network Related Entities | Represents a Uniform Resource Locator (URL), often used in web-basedattacks or phishing campaigns.                                                                                               |
| Network Connection | **Network Entities** : Network Related Entities | Represents a network connection, including source and destination IPs, ports, and protocols. This entity is critical for detecting suspicious or unauthorized communication between systems.     |
| Authentication     | **Host Entities** : Host Related Entities       | Represents an authentication attempt, including the user, source IP, and success or failure status. Authentication events are critical for detecting brute force attacks or unauthorized access. |

**⚠️ Detectors**

_❌ No detectors mentioned_

**🌐 Examples**

_❌ No examples mentioned_



### Non-Standard Content in Cisco ASA WebVPN Authentication Response

🪪 **UUID** : `cef505da-e628-469b-ad75-1a19091d31a6`

> Detects Cisco ASA WebVPN authentication responses that embed
data in the XML `message` element in a manner inconsistent with
legitimate authentication outcomes [1].

LINE VIPER exfiltrates task results by returning them embedded
within the `message` element of the WebVPN XML authentication
response. Legitimate ASA authentication responses contain
human-readable error or status strings in this field (e.g.,
"Authentication failed", "Please enter credentials"). Attacker-
controlled responses will contain base64-encoded or encrypted
data blobs.

Detection criteria:
- WebVPN authentication responses (HTTP 200 OK) where the
  `message` XML element contains high-entropy, non-printable,
  or base64-like content
- Response `message` field length significantly exceeding
  baseline for authentication status messages (>200 bytes
  without expected authentication UI text)
- Responses including standard security headers
  (X-Frame-Options, Strict-Transport-Security) alongside an
  anomalous `message` element — legitimate denials typically
  include only basic HTML error pages
- Asymmetric session patterns: multiple auth requests from the
  same IP that generate non-standard XML responses rather than
  standard redirect or HTML authentication pages

Requires visibility into outbound ASA HTTPS responses, achievable
via inline inspection or traffic mirroring.


**🔎 Data Visibility**

- **Availability** : Not Available
- **Requirements** : `- Outbound HTTPS response inspection for Cisco ASA WebVPN
  traffic (requires TLS inspection or traffic mirroring)
- Ability to parse and analyse XML response bodies from ASA
- Baseline corpus of legitimate ASA WebVPN response patterns

Preferred log sources:
- Network TAP/SPAN with inline TLS inspection
- NGFW with SSL decryption and response body inspection
- Zeek SSL/TLS logs with response body extraction
`

_💾 Possible logsources_

_❌ No logsources mentioned_

**🧲 Related Entities**

| Name               | Category                                        | Description                                                                                                                                                                                  |
|:-------------------|:------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IP Address         | **Network Entities** : Network Related Entities | Represents an IPv4 or IPv6 address associated with a host or networkconnection.                                                                                                              |
| Network Connection | **Network Entities** : Network Related Entities | Represents a network connection, including source and destination IPs, ports, and protocols. This entity is critical for detecting suspicious or unauthorized communication between systems. |
| URL                | **Network Entities** : Network Related Entities | Represents a Uniform Resource Locator (URL), often used in web-basedattacks or phishing campaigns.                                                                                           |
| Hostname           | **Host Entities** : Host Related Entities       | Represents the name of a host or device in the network.                                                                                                                                      |

**⚠️ Detectors**

_❌ No detectors mentioned_

**🌐 Examples**

_❌ No examples mentioned_



## References



**🕊️ Publicly available resources**

- [_1_] https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf

[1]: https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf

