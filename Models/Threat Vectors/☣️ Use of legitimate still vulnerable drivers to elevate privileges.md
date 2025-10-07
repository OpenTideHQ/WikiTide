

# ☣️ Use of legitimate still vulnerable drivers to elevate privileges

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1547.006 : Boot or Logon Autostart Execution: Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006 'Adversaries may modify the kernel to automatically execute programs on system boot Loadable Kernel Modules LKMs are pieces of code that can be loaded '), [T1068 : Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges Exploitation of a software vulnerability occurs when an adversary'), [T1547 : Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547 'Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level ')



---

`🔑 UUID : a5761988-391d-4cd3-8ade-690bd3315943` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-08-18` **|** `🗓️ Last Modification : 2025-08-22` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Threat actors can use legitimate and code-signed, but vulnerable drivers to 
> execute kernel-level code in order to elevate privileges or disable security 
> products. Such drivers can allow malicious actors to manipulate system 
> components, processes, maintain persistence on a system and evade security 
> products ref [1].
> 
> Microsoft and other vendors have created and maintain vulnerable driver 
> lists ref [2], [6], [7], for example to thwart and isolate drivers which are 
> vulnerable or with a high risk for explaoitation. The drivers with a 
> previously discovered vulnerabilites can also be considered for review and
> as good candidates for a block list or monitoring.  
> 
> The vulnerable signed drivers can come from a variety of vendors such as,
> but not limited to, ASROCK, ASUSTeK, IBM.  
> 
> ### List of some vulnerable signed drivers, which have been exploited in 
> the past
> 
> - `win32k.sys` - it's a kernel-mode driver that has been exploited in
>    various ways, including elevation of privilege (EoP) vulnerabilities.
> - `splwow64.sys` - this is a vulnerable driver which lets local code
>   escalation by abusing the print stack broker.
> - `dxgkrnl.sys` - this driver is responsible for graphics rendering and has
>   been vulnerable to exploits. It's related to a validation flaw enabling
>   local EoP in the DirectX graphics kernel driver.
> - `tdx.sys`: The TDx driver has been exploited in the past, including a
>   vulnerability that allows remote code execution (RCE). Other vulnerability
>   buffer over-read allows local EoP on multiple Windows versions; patched
>   July 2025.
> - `splwow64.sys` - this driver is responsible for print spooling and has
>    been vulnerable to exploits.
> - `cng.sys` - the Cryptography Next Generation (CNG) driver has been
>   exploited, including a vulnerability (CVE-2020-1145) that allowed EoP.
> - `msrpc.sys` - it's Microsoft Remote Procedure Call (MSRPC) driver has been
>   vulnerable to exploits. 
> - `ucx01000.sys` - this driver is part of the USB driver stack and has been
>   exploited. 
> - `ndis.sys` - the Network Driver Interface Specification (NDIS) driver has
>   been vulnerable to exploits. Example for an exploit: EoP precedent where
>   buffer length checks were insufficient.  
> - `wdf01000.sys` - this is Windows Driver Framework (WDF) driver which can
>    be exploited by the threat actors for privilege escalation and other
>    purposes.
> - `storport.sys` - the Storage Port driver can be vulnerable to exploits.
> 



## 🖥️ Terrain 

 > A threat actor uses software vulnerabilities in legitimate Windows or other 
> driver. The adversary already has local code execution (e.g., user context),
> can trigger the vulnerable IOCTL/syscall surface, and the system is not yet
> patched.  
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Aliases                                                                                                                                                                                                                                                   | Source                     | Sighting                                                                                                                                                                                                                                                                                                                                                                                         | Reference                                                                                                                    |
|:-------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------|
| Turla              | A 2014 Guardian article described Turla as: 'Dubbed the Turla hackers, initial intelligence had indicated western powers were key targets, but it was later determined embassies for Eastern Bloc nations were of more interest. Embassies in Belgium, Ukraine, China, Jordan, Greece, Kazakhstan, Armenia, Poland, and Germany were all attacked, though researchers from Kaspersky Lab and Symantec could not confirm which countries were the true targets. In one case from May 2012, the office of the prime minister of a former Soviet Union member country was infected, leading to 60 further computers being affected, Symantec researchers said. There were some other victims, including the ministry for health of a Western European country, the ministry for education of a Central American country, a state electricity provider in the Middle East and a medical organisation in the US, according to Symantec. It is believed the group was also responsible for a much - documented 2008 attack on the US Central Command. The attackers - who continue to operate - have ostensibly sought to carry out surveillance on targets and pilfer data, though their use of encryption across their networks has made it difficult to ascertain exactly what the hackers took.Kaspersky Lab, however, picked up a number of the attackers searches through their victims emails, which included terms such as Nato and EU energy dialogue Though attribution is difficult to substantiate, Russia has previously been suspected of carrying out the attacks and Symantecs Gavin O’ Gorman told the Guardian a number of the hackers appeared to be using Russian names and language in their notes for their malicious code. Cyrillic was also seen in use.' | Snake, VENOMOUS Bear, Group 88, Waterbug, WRAITH, Uroburos, Pfinet, TAG_0530, KRYPTON, Hippo Team, Pacifier APT, Popeye, SIG23, IRON HUNTER, MAKERSMARK, ATK13, G0010, ITG12, Blue Python, SUMMIT, UNC4210, Secret Blizzard, UAC-0144, UAC-0024, UAC-0003 | 🌌 MISP Threat Actor Galaxy | No documented sighting                                                                                                                                                                                                                                                                                                                                                                           | No documented references                                                                                                     |
| [Enterprise] Turla | [Turla](https://attack.mitre.org/groups/G0010) is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB).  They have compromised victims in over 50 countries since at least 2004, spanning a range of industries including government, embassies, military, education, research and pharmaceutical companies. [Turla](https://attack.mitre.org/groups/G0010) is known for conducting watering hole and spearphishing campaigns, and leveraging in-house tools and malware, such as [Uroburos](https://attack.mitre.org/software/S0022).(Citation: Kaspersky Turla)(Citation: ESET Gazer Aug 2017)(Citation: CrowdStrike VENOMOUS BEAR)(Citation: ESET Turla Mosquito Jan 2018)(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | BELUGASTURGEON, Group 88, IRON HUNTER, Krypton, Secret Blizzard, Snake, Venomous Bear, Waterbug, WhiteBear                                                                                                                                                | 🗡️ MITRE ATT&CK Groups     | Turla is a Russian affiliated sophisticated threat actor group known inthe time to use the technique bring your own vulnerable driver (BYOVD)ref [3].                                                                                                                                                                                                                                            | https://www.eset.com/us/about/newsroom/corporate-blog/taking-down-turla-balancing-act-between-visibility-usability-with-eset |
| Caramel Tsunami    | Caramel Tsunami is a threat actor that specializes in spyware attacks. They have recently resurfaced with an updated toolset and zero-day exploits, targeting specific victims through watering hole attacks. Candiru has been observed exploiting vulnerabilities in popular browsers like Google Chrome and using third-party signed drivers to gain access to the Windows kernel. They have also been linked to other spyware vendors and have been associated with extensive abuses of their surveillance tools.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | SOURGUM, Candiru                                                                                                                                                                                                                                          | 🌌 MISP Threat Actor Galaxy | Candiru is an Israeli based mercenary spyware firm. Their productoffering includes solutions for spying on computers, mobile devices,and cloud accounts. One of their campaigns (DevilsTongue spyware) isassociated with exploitation of a native Windows drivers. Theyinitially dropped on the system HW.sys legitimate vulnerable driverand after used it to elevate their privileges ref [4]. | https://securityaffairs.com/133546/intelligence/candiru-chrome-zero-day.html                                                 |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🥸 Privilege Escalation`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : The result of techniques that provide an attacker with higher permissions on a system or network.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 Customer`](http://veriscommunity.net/enums.html#section-asset) : People - Customer
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🛠️ Virtual Machines`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

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

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.securityweek.com/dozens-of-kernel-drivers-allow-attackers-to-alter-firmware-escalate-privileges
- [_2_] https://www.polimetro.com/en/What-is-Microsoft-Vulnerable-Driver-Blocklist
- [_3_] https://www.eset.com/us/about/newsroom/corporate-blog/taking-down-turla-balancing-act-between-visibility-usability-with-eset
- [_4_] https://securityaffairs.com/133546/intelligence/candiru-chrome-zero-day.html
- [_5_] https://www.csoonline.com/article/4034988/akira-affiliates-abuse-legitimate-windows-drivers-to-evade-detection-in-sonicwall-attacks.html
- [_6_] https://www.loldrivers.io/
- [_7_] https://github.com/splunk/security_content/blob/develop/lookups/loldrivers.csv

[1]: https://www.securityweek.com/dozens-of-kernel-drivers-allow-attackers-to-alter-firmware-escalate-privileges
[2]: https://www.polimetro.com/en/What-is-Microsoft-Vulnerable-Driver-Blocklist
[3]: https://www.eset.com/us/about/newsroom/corporate-blog/taking-down-turla-balancing-act-between-visibility-usability-with-eset
[4]: https://securityaffairs.com/133546/intelligence/candiru-chrome-zero-day.html
[5]: https://www.csoonline.com/article/4034988/akira-affiliates-abuse-legitimate-windows-drivers-to-evade-detection-in-sonicwall-attacks.html
[6]: https://www.loldrivers.io/
[7]: https://github.com/splunk/security_content/blob/develop/lookups/loldrivers.csv

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


