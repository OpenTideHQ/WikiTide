

# ☣️ Passing SeDebugPrivilege to AdjustTokenPrivilege API elevating privileges of a running process

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1134.001 : Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001 'Adversaries may duplicate then impersonate another users existing token to escalate privileges and bypass access controls For example, an adversary ca')



---

`🔑 UUID : 5d373113-18f9-41bb-bdde-3abbfa53cb86` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-11-16` **|** `🗓️ Last Modification : 2022-11-17` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> A threat actor can attempt to escalate privileges from a user or 
> administrator context to NT SYSTEM by using the SeDebugPrivilege to adjust 
> the memory of running process with a call to the AdjustTokenPrivilege API. 
> This method uses built-in Windows APIs and commands to escalate privileges 
> by changing the privileges of the running process in-memory. See Palantir 
> reference. 
> 
> The intention of access token impersonation/theft is to grant a process the 
> same permissions as another running process with a specific context, often 
> NT SYSTEM. This may increase the capabilities of the now-elevated process 
> or reduce its probability of detection.
> 
> For access token impersonation an adversary can use standard command-line 
> shell to initiate 'runas' commands or to use payloads that call Windows 
> token APIs directly. The changes in Windows API calls can manipulate 
> access tokens for further account access and malicious purposes. 
> 



## 🖥️ Terrain 

 > On an already compromised Windows endpoint in a user or administrator 
> context that has SeDebugPrivilege assigned (rarely on user context). 
> Windows servers and windows workstations/laptops - anything 
> Windows.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🥸 Privilege Escalation`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : The result of techniques that provide an attacker with higher permissions on a system or network.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🔐 Auth token`](http://veriscommunity.net/enums.html#section-asset) : User Device - Authentication token or device
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 Windows API`](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) : The Windows API, informally WinAPI, is Microsoft's core set of application programming interfaces (APIs) available in the Microsoft Windows operating systems. The name Windows API collectively refers to several different platform implementations that are often referred to by their own names (for example, Win32 API). Almost all Windows programs interact with the Windows API.
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`💅 Modify privileges`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify privileges or permissions
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://blog.malwarebytes.com/threat-analysis/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor/
- [_2_] https://attack.mitre.org/techniques/T1134/
- [_3_] https://pentestlab.blog/2017/04/03/token-manipulation/
- [_4_] https://adsecurity.org/?page_id=1821#TOKENElevate
- [_5_] https://juggernaut-sec.com/dumping-credentials-mimikatz-lsa-dump/
- [_6_] https://attack.mitre.org/techniques/T1134/001/
- [_7_] https://docs.rapid7.com/metasploit/meterpreter-getsystem/
- [_8_] https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf
- [_9_] https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e

[1]: https://blog.malwarebytes.com/threat-analysis/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor/
[2]: https://attack.mitre.org/techniques/T1134/
[3]: https://pentestlab.blog/2017/04/03/token-manipulation/
[4]: https://adsecurity.org/?page_id=1821#TOKENElevate
[5]: https://juggernaut-sec.com/dumping-credentials-mimikatz-lsa-dump/
[6]: https://attack.mitre.org/techniques/T1134/001/
[7]: https://docs.rapid7.com/metasploit/meterpreter-getsystem/
[8]: https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf
[9]: https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


