

# ☣️ Cobalt Strike Beacon deployment via Metasploit downloader

🔥 **Criticality:Severe** 🚨 : A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1071.001 : Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detectionnetwork filtering by blending in with exis'), [T1573.001 : Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001 'Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections p'), [T1105 : Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105 'Adversaries may transfer tools or other files from an external system into a compromised environment Tools or files may be copied from an external adv'), [T1059 : Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries These interfaces and languages provide ways of interac')



---

`🔑 UUID : 7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2026-02-09` **|** `🗓️ Last Modification : 2026-02-09` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> ## Executive Summary
> 
> Cobalt Strike Beacon was deployed as the final payload in all three infection chains 
> of the Notepad++ supply chain attack, using Metasploit downloader shellcode as the 
> delivery mechanism. This represents a sophisticated command and control (C2) 
> infrastructure deployment using commercial-grade post-exploitation frameworks.
> 
> ## Technical Overview
> 
> ### Deployment Mechanism
> 
> Metasploit downloader shellcode is executed as a second-stage payload across multiple 
> infection chains. The downloader retrieves Cobalt Strike Beacon from attacker-controlled 
> URLs and establishes encrypted C2 communications.
> 
> ### Beacon Configuration Characteristics
> 
> **Encryption**: All Cobalt Strike Beacon configurations are encrypted using XOR 
> cipher with the key **"CRAZY"**. This consistent encryption key across multiple 
> payloads suggests a common operator or shared infrastructure.
> 
> **User-Agent Strings**:
> ```
> Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
> Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
> ```
> 
> These User-Agent strings mimic legitimate Chrome browser traffic to blend with 
> normal network activity.
> 
> ### Deployment Location
> 
> Rapid7 researchers identified Cobalt Strike Beacon deployed to:
> ```
> C:\ProgramData\USOShared\
> ```
> 
> This directory mimics Windows Update service locations (USO = Update Session Orchestrator) 
> to evade detection through legitimate-appearing file paths.
> 
> ## Indicators of Compromise (IOCs)
> 
> ### Metasploit Downloader URLs
> 
> These URLs are used by Metasploit downloader shellcode to retrieve Cobalt Strike Beacon:
> 
> ```
> https://45.77.31[.]210/users/admin
> https://cdncheck.it[.]com/users/admin
> https://safe-dns.it[.]com/help/Get-Start
> https://api.wiresguard[.]com/users/admin
> ```
> 
> **Pattern**: Three of four URLs follow the `/users/admin` pattern, suggesting 
> automated generation or templated infrastructure setup.
> 
> ### Cobalt Strike Beacon C2 URLs
> 
> Primary C2 infrastructure identified by Kaspersky:
> 
> ```
> https://45.77.31[.]210/api/update/v1
> https://45.77.31[.]210/api/FileUpload/submit
> https://cdncheck.it[.]com/api/update/v1
> https://cdncheck.it[.]com/api/Metadata/submit
> https://cdncheck.it[.]com/api/getInfo/v1
> https://cdncheck.it[.]com/api/FileUpload/submit
> https://safe-dns.it[.]com/resolve
> https://safe-dns.it[.]com/dns-query
> https://api.wiresguard[.]com/update/v1
> https://api.wiresguard[.]com/api/FileUpload/submit
> ```
> 
> **Pattern Analysis**:
> - Multiple C2 URLs use `/api/FileUpload/submit` endpoint
> - Several use `/api/update/v1` or similar versioned API patterns
> - DNS-themed C2 domains use DNS-related paths (`/resolve`, `/dns-query`)
> - API versioning suggests organized infrastructure management
> 
> ### Additional C2 Infrastructure (Rapid7 Findings)
> 
> ```
> http://59.110.7[.]32:8880/uffhxpSy
> http://59.110.7[.]32:8880/api/getBasicInfo/v1
> http://124.222.137[.]114:9999/3yZR31VK
> http://124.222.137[.]114:9999/api/updateStatus/v1
> ```
> 
> **Key Observations**:
> - These use HTTP instead of HTTPS, potentially indicating different operational phases
> - Non-standard ports (8880, 9999) for HTTP traffic
> - Random path components mixed with API-style paths
> - Versioned API endpoints consistent with primary infrastructure
> 
> ### Malicious Domains
> 
> ```
> cdncheck.it[.]com
> safe-dns.it[.]com
> wiresguard[.]com (typosquat of wireguard.com)
> ```
> 
> **Domain Strategy**:
> - DNS/CDN themed domains for legitimacy
> - Typosquatting of legitimate services (WireGuard VPN)
> - IT-focused naming to blend with enterprise network traffic
> 
> ### Malicious IP Addresses
> 
> ```
> 45.77.31.210
> 59.110.7.32
> 124.222.137.114
> ```
> 
> ### Cryptographic Indicators
> 
> **XOR Encryption Key**: `CRAZY`
> 
> This key is consistently used across multiple Cobalt Strike Beacon configurations, 
> serving as a strong indicator of related campaigns or shared infrastructure.
> 
> ## Attack Flow
> 
> 1. **Initial Compromise**: Victim system compromised via Notepad++ supply chain attack
> 2. **Metasploit Downloader Execution**: First-stage payload executes Metasploit downloader shellcode
> 3. **Beacon Retrieval**: Downloader contacts URLs like `/users/admin` to fetch Cobalt Strike Beacon
> 4. **Beacon Deployment**: Beacon is written to disk (e.g., `C:\ProgramData\USOShared\`)
> 5. **C2 Establishment**: Beacon initiates encrypted C2 communications using HTTPS
> 6. **Persistent Access**: Attacker maintains command and control for espionage or lateral movement
> 
> ## Infrastructure Commonalities
> 
> Analysis reveals consistent patterns across the infrastructure:
> 
> 1. **URL Patterns**: Frequent use of `/users/admin` for payload delivery
> 2. **API Design**: Versioned API endpoints (e.g., `/api/update/v1`, `/api/updateStatus/v1`)
> 3. **File Upload Endpoints**: Multiple C2 servers expose `/api/FileUpload/submit`
> 4. **Encryption**: Uniform use of XOR with key "CRAZY"
> 5. **User-Agent**: Consistent Chrome User-Agent strings across campaigns
> 
> These similarities indicate:
> - Shared infrastructure or operational templates
> - Likely common threat actor or coordinated operation
> - Professional infrastructure management and organization
> 
> ## Detection Opportunities
> 
> ### Network Detection
> 
> 1. **URL Pattern Matching**:
>    - Monitor for HTTP(S) requests to `/users/admin` paths
>    - Alert on connections to `/api/FileUpload/submit` endpoints
>    - Detect versioned API patterns (`/api/*/v1`)
> 
> 2. **Domain Reputation**:
>    - Block/alert on connections to IOC domains
>    - Monitor for typosquat domains of legitimate services
>    - Flag DNS-themed domains in non-DNS contexts
> 
> 3. **SSL/TLS Inspection**:
>    - Inspect HTTPS traffic for Cobalt Strike malleable C2 profiles
>    - Look for consistent User-Agent patterns
>    - Detect encrypted payloads with XOR patterns
> 
> 4. **Port Usage**:
>    - Monitor HTTP traffic on non-standard ports (8880, 9999)
> 
> ### Host-Based Detection
> 
> 1. **File System Monitoring**:
>    - Alert on file creation in `C:\ProgramData\USOShared\` by non-system processes
>    - Monitor for PE files in unusual locations with network activity
> 
> 2. **Process Monitoring**:
>    - Detect Metasploit downloader shellcode execution patterns
>    - Monitor for process injection behaviors common to Cobalt Strike
>    - Alert on unusual parent-child process relationships
> 
> 3. **Memory Analysis**:
>    - Scan for XOR-encrypted Cobalt Strike configurations in memory
>    - Search for the XOR key "CRAZY" in process memory
>    - Detect Cobalt Strike reflective DLL injection techniques
> 
> 4. **Registry Monitoring**:
>    - Watch for persistence mechanisms in Run keys or scheduled tasks
> 
> ### Behavioral Detection
> 
> 1. **Beaconing Activity**:
>    - Detect periodic network connections at regular intervals
>    - Monitor for consistent User-Agent strings across multiple connections
>    - Identify low-volume, high-frequency HTTPS connections
> 
> 2. **Data Exfiltration**:
>    - Monitor POST requests to `/api/FileUpload/submit` endpoints
>    - Alert on large data transfers to external IPs
> 
> 3. **Lateral Movement**:
>    - Detect credential theft attempts (common Cobalt Strike capability)
>    - Monitor for lateral movement using SMB, WMI, or PsExec
> 
> ## MITRE ATT&CK Mapping
> 
> ### T1071.001 - Application Layer Protocol: Web Protocols
> 
> Cobalt Strike Beacon uses HTTPS/HTTP for C2 communications to blend with legitimate 
> web traffic. The use of standard ports (443, 80) and Chrome User-Agents mimics 
> normal browser behavior.
> 
> ### T1573.001 - Encrypted Channel: Symmetric Cryptography
> 
> Beacon configurations are encrypted using XOR cipher with the key "CRAZY". 
> Additionally, HTTPS provides transport layer encryption for C2 communications.
> 
> ### T1105 - Ingress Tool Transfer
> 
> Metasploit downloader fetches Cobalt Strike Beacon from remote URLs, transferring 
> the post-exploitation framework to the compromised system.
> 
> ### T1059 - Command and Scripting Interpreter
> 
> Cobalt Strike Beacon provides interactive command execution capabilities, allowing 
> operators to execute commands and scripts on compromised systems.
> 
> ## Mitigation Recommendations
> 
> ### Immediate Actions
> 
> 1. **Network Blocking**:
>    - Block all IOC IPs and domains at firewall/proxy level
>    - Implement DNS sinkholing for malicious domains
> 
> 2. **Threat Hunting**:
>    - Search for files in `C:\ProgramData\USOShared\` created by non-system processes
>    - Hunt for network connections to IOC infrastructure
>    - Scan memory for XOR key "CRAZY" or Cobalt Strike artifacts
> 
> 3. **Endpoint Isolation**:
>    - Isolate systems showing signs of Cobalt Strike infection
>    - Prevent lateral movement through network segmentation
> 
> ### Long-Term Measures
> 
> 1. **EDR Deployment**:
>    - Deploy EDR solutions with Cobalt Strike detection capabilities
>    - Enable memory scanning and behavioral detection
> 
> 2. **Network Monitoring**:
>    - Implement SSL/TLS inspection for encrypted traffic
>    - Deploy IDS/IPS rules for Cobalt Strike indicators
>    - Monitor for beaconing behavior patterns
> 
> 3. **Application Control**:
>    - Implement application whitelisting to prevent unauthorized executables
>    - Block execution from non-standard directories like `C:\ProgramData\USOShared\`
> 
> 4. **Supply Chain Security**:
>    - Verify software update integrity through code signing
>    - Restrict software installation to official channels only
> 
> 5. **User Education**:
>    - Train users on supply chain attack risks
>    - Educate on identifying suspicious system behavior
> 
> ## Threat Actor Assessment
> 
> The consistent infrastructure patterns, encryption keys, and professional operational 
> security suggest a coordinated threat actor or shared infrastructure among related 
> groups. The targeting of government and financial sectors across multiple countries 
> indicates espionage or financial crime motivations.
> 
> **Sophistication Level**: High
> - Use of commercial-grade post-exploitation framework (Cobalt Strike)
> - Organized C2 infrastructure with versioned APIs
> - Persistent operations across multiple months
> - Supply chain compromise capabilities
> 
> **Operational Security**:
> - HTTPS encryption for C2 traffic
> - Legitimate-appearing domain names and URL paths
> - Mimicking Windows system directories for file placement
> - Use of common User-Agent strings
> 
> ## Conclusion
> 
> The deployment of Cobalt Strike Beacon via Metasploit downloader represents a 
> critical threat to organizations worldwide. The consistent use of specific encryption 
> keys, infrastructure patterns, and professional tradecraft indicates an organized 
> and persistent adversary. Organizations should prioritize detection and mitigation 
> efforts focusing on the specific IOCs and behavioral patterns identified in this 
> threat vector.
> 
> Immediate action is required to:
> 1. Detect existing infections through IOC sweeps
> 2. Block C2 communications through network controls
> 3. Hunt for artifacts in memory and on disk
> 4. Implement long-term defenses against post-exploitation frameworks
> 
> This threat vector should be considered **CRITICAL** priority for incident response 
> and threat hunting operations.
> 



## 🖥️ Terrain 

 > Windows workstations and laptops, particularly developer environments, that have 
> been compromised through the Notepad++ supply chain attack. The Metasploit 
> downloader acts as a second-stage payload fetching mechanism, downloading and 
> executing Cobalt Strike Beacon from attacker-controlled infrastructure. This 
> affects organizations across government, financial services, and IT sectors 
> in multiple countries including Vietnam, El Salvador, Australia, and the Philippines.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects

```mermaid

mindmap
Root[☣️ Cobalt Strike Beacon deployment via Metasploit downloader]
    
      🎯 Detect Notepad:: Supply Chain Compromise Activity 
          📡 NSIS Installer Deployment from Notepad:: Updater 
          📡 System Reconnaissance Commands Following Software Update 
          📡 Data Exfiltration to temp.sh Web Service 
          📡 Suspicious DLL SideLoading and ExploitBased Execution 
          📡 Cobalt Strike Beacon C2 Communication 
    


```




 **Descendants** 

| 🎯 Detection Objectives                                                                                                                                                                                                                                                                                        | 📡 Detection Objective Signals (5)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 🛡️ Detection Models    | 🚨 Detection Rules    |
|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------|:---------------------|
| [Detect Notepad++ Supply Chain Compromise Activity](../Detection%20Objectives/🎯%20Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity.md 'This detection objective addresses the sophisticated supply chain compromiseof Notepad update infrastructure that occurred between July and October 20...') | [Detect Notepad++ Supply Chain Compromise Activity::System Reconnaissance Commands Following Software Update](Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity#system-reconnaissance-commands-following-software-update.md 'Detects sequences of system reconnaissance commands characteristic of theNotepad supply chain attack discovery phase Attackers executed combinationsof...')<br>[Detect Notepad++ Supply Chain Compromise Activity::Suspicious DLL Side-Loading and Exploit-Based Execution](Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity#suspicious-dll-side-loading-and-exploit-based-execution.md 'Detects malicious execution via legitimate software abuse, including DLLside-loading and exploitation of vulnerable legitimate executables TheNotepad ...')<br>[Detect Notepad++ Supply Chain Compromise Activity::Data Exfiltration to temp.sh Web Service](Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity#data-exfiltration-to-temp.sh-web-service.md 'Detects data exfiltration to the tempsh temporary file sharing service,used by attackers to stage reconnaissance data and avoid direct C2 communicatio...')<br>[Detect Notepad++ Supply Chain Compromise Activity::NSIS Installer Deployment from Notepad++ Updater](Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity#nsis-installer-deployment-from-notepad++-updater.md 'Detects the execution of NSIS Nullsoft Scriptable Install System installerslaunched by GUPexe, the legitimate Notepad update component The maliciousup...')<br>[Detect Notepad++ Supply Chain Compromise Activity::Cobalt Strike Beacon C2 Communication](Detect%20Notepad++%20Supply%20Chain%20Compromise%20Activity#cobalt-strike-beacon-c2-communication.md 'Detects network communication to known Cobalt Strike C2 infrastructureassociated with the Notepad supply chain campaign All observed infectionchains u...') | ❌ No Detection Models  | ❌ No Detection Rules |



 --- 

### ⛓️ Threat Chaining

```mermaid

flowchart LR

7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a[Cobalt Strike Beacon deployment via Metasploit downloader]
8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22[Notepad++ supply chain attack]

subgraph Command & Control
7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a
end
subgraph Delivery
8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22
end

OS::Windows::Desktop[(OS::Windows::Desktop)]

7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a -.->|targets| OS::Windows::Desktop
8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22 -.->|targets| OS::Windows::Desktop

7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a -->|implements| 8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22

```


<details>
<summary>Expand chaining data</summary>

| ☣️ Vector                                                                                                                                                                                                                                                                                                                  | ⛓️ Link                 | 🎯 Target                                                                                                                                                                                                                                                     | ⛰️ Terrain                                                                                                                                                                                                                                                                                                                                                                                                    | 🗡️ ATT&CK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Cobalt Strike Beacon deployment via Metasploit downloader](../Threat%20Vectors/☣️%20Cobalt%20Strike%20Beacon%20deployment%20via%20Metasploit%20downloader.md '## Executive SummaryCobalt Strike Beacon was deployed as the final payload in all three infection chains of the Notepad supply chain attack, using Met...') | `atomicity::implements` | [Notepad++ supply chain attack](../Threat%20Vectors/☣️%20Notepad++%20supply%20chain%20attack.md '## Executive SummaryOn February 2, 2026, Notepad developers disclosed a critical supply chain compromise affecting their update infrastructure The att...') | Organizations and individuals using Notepad++ text editor on Windows systems,  particularly those with automatic update mechanisms enabled. The attack targeted  the legitimate update infrastructure, delivering malicious payloads disguised  as authentic software updates. Victims were distributed globally across multiple  sectors including government, financial services, and IT service providers. | [T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002 'Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise Supply chain comprom'), [T1071 : Application Layer Protocol](https://attack.mitre.org/techniques/T1071 'Adversaries may communicate using OSI application layer protocols to avoid detectionnetwork filtering by blending in with existing traffic Commands to'), [T1059 : Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries These interfaces and languages provide ways of interac'), [T1574 : Hijack Execution Flow](https://attack.mitre.org/techniques/T1574 'Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs Hijacking execution flow can be for the purpo') |

</details>
&nbsp; 


---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🕹️ Command & Control`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques that allow attackers to communicate with controlled systems within a target network.

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🚨 Highly significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`⚖️ Legal and regulatory`](http://veriscommunity.net/enums.html#section-impact) : Legal and regulatory costs
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`😱 Almost certain`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Nearly certain - 95-99%

---





## 🌐 Threat Surface

- ` OS::Windows::Desktop` — Microsoft Windows desktop editions


### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://securelist.com/notepad-supply-chain-attack/115382/
- [_2_] https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/

[1]: https://securelist.com/notepad-supply-chain-attack/115382/
[2]: https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


