

# ☣️ Possible Smart App Control Evasion Attempt

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1112 : Modify Registry](https://attack.mitre.org/techniques/T1112 'Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and executionAcces'), [T1195 : Supply Chain Compromise](https://attack.mitre.org/techniques/T1195 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromiseSu'), [T1204 : User Execution](https://attack.mitre.org/techniques/T1204 'An adversary may rely upon specific actions by a user in order to gain execution Users may be subjected to social engineering to get them to execute m')



---

`🔑 UUID : dcf021a5-2846-40b4-8189-2695a7a32b9a` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-06-12` **|** `🗓️ Last Modification : 2025-06-24` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Smart App Control is a cloud-powered security feature in Windows 11 designed to 
> block malicious, untrusted, and potentially unwanted applications from running. 
> It uses a combination of reputation checks and digital signatures to determine whether 
> an application is safe to execute. If an app is not recognized or is considered 
> risky, SAC blocks its execution.
> 
> ## Main Evasion Techniques
> 
> **1. Registry Manipulation**
> Registry manipulation is a common method in broader Windows attack vectors for disabling 
> or bypassing security features. Adversaries may attempt to:
> - **Disable or modify SAC-related registry keys** to weaken or turn off the feature.
> - **Tamper with security policy settings** stored in the registry to lower protection levels.
>   
> **2. Code-Signing and Certificate Abuse**
> One of the most prevalent methods to bypass SAC is to sign malware with a legitimate 
> code-signing certificate. Attackers increasingly use Extended Validation (EV) certificates, 
> which require identity verification, by impersonating legitimate businesses to obtain 
> them. This allows malware to appear trustworthy and slip past SAC’s checks.
> 
> **3. Reputation-Based Evasion**
> - **Reputation Hijacking:** Attackers repurpose trusted applications (like script interpreters) 
> to load and execute malicious code without triggering alerts.
> - **Reputation Seeding:** Attackers use seemingly innocuous binaries to trigger 
> malicious behavior after a certain time or event.
> - **Reputation Tampering:** Attackers alter parts of legitimate binaries to inject 
> shellcode without losing their good reputation.
> 
> **4. LNK Stomping**
> Attackers exploit the way Windows handles shortcut (LNK) files. By crafting LNK 
> files with non-standard target paths or structures, they can remove the "mark-of-the-web" 
> (MotW) tag before security checks are performed, allowing malicious payloads to 
> bypass SAC.
> 
> **5. Social Engineering**
> Attackers trick users into overriding security warnings or disabling SAC by posing 
> as legitimate sources or using persuasive tactics.
> 
> **6. Living-Off-The-Land Binaries (LOLBins)**
> Attackers abuse signed Microsoft-supplied binaries (e.g., `mshta.exe`, 
> `rundll32.exe`, `regsvr32.exe`) to proxy execution of malicious scripts 
> and payloads, which Smart App Control might not block if the binary is 
> considered trusted.
> 



## 🖥️ Terrain 

 > Adverdaries need to sign malware with a legitimate or fraudulently obtained code-signing 
> certificate—especially Extended Validation (EV) certificates.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🏃🏽 Defense Evasion`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques an attacker may specifically use for evading detection or avoiding other defenses.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `🌏 OSINT` : Data publicly available to attackers used during reconnaissance.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🛠️ Virtual Machines`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🛠️ Software Containers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 Windows API`](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) : The Windows API, informally WinAPI, is Microsoft's core set of application programming interfaces (APIs) available in the Microsoft Windows operating systems. The name Windows API collectively refers to several different platform implementations that are often referred to by their own names (for example, Win32 API). Almost all Windows programs interact with the Windows API.
 - [`🗃️ Critical Documents`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` PowerShell` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`💅 Modify privileges`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify privileges or permissions
 - [`✨ Modify data`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify stored data or content

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://thehackernews.com/2024/08/researchers-uncover-flaws-in-windows.html
- [_2_] https://thecyberexpress.com/windows-smart-app-control-smartscreen-bypass/
- [_3_] https://www.securitynewspaper.com/2024/08/06/five-techniques-for-bypassing-microsoft-smartscreen-and-smart-app-control-sac-to-run-malware-in-windows/
- [_4_] https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2/

[1]: https://thehackernews.com/2024/08/researchers-uncover-flaws-in-windows.html
[2]: https://thecyberexpress.com/windows-smart-app-control-smartscreen-bypass/
[3]: https://www.securitynewspaper.com/2024/08/06/five-techniques-for-bypassing-microsoft-smartscreen-and-smart-app-control-sac-to-run-malware-in-windows/
[4]: https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


