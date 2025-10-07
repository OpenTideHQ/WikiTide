

# ☣️ SharePoint ToolShell vulnerabilities

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1190 : Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network The weakness in the system can be a s'), [T1212 : Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212 'Adversaries may exploit software vulnerabilities in an attempt to collect credentials Exploitation of a software vulnerability occurs when an adversar'), [T1078 : Valid Accounts](https://attack.mitre.org/techniques/T1078 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense ')



---

`🔑 UUID : 55227203-38dc-406b-943a-9c1c6023d1cd` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-07-28` **|** `🗓️ Last Modification : 2025-08-16` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> SharePoint zero-day vulnerabilities, known also as `ToolShell` are affecting
> on-premise Microsoft SharePoint servers, which enable the attackers to
> execute code on SharePoint servers without authentication, bypassing
> security mechanisms. This vulnerabilities are considered with a high
> security risk because they may lead to a remote code execution (RCE)
> and a fully compromise of a SharePoint environment. 
> 
> What is known until now for these vulnerabilities is that a threat actor
> deploys initially a malicious ASPX file `spinstall0.aspx`, also knows as
> `SharpyShell`. The malicious file purpose is to extract and leak
> cryptographic secrets from the SharePoint server using a simple GET request.
> The goal of the threat actor is to obtain the server's MachineKey
> configuration, including the critical ValidationKey , which are essential
> for generating valid payloads ref [1].    
> 
> With these keys, the attackers can effectively turn any authenticated
> SharePoint request into a remote code execution opportunity, bypassing the
> need for credentials and gaining full control of the server.  
> 
> The attacker then uses a tool called `ysoserial` to craft their own valid
> SharePoint token for remote code execution with full persistence and no
> authentication ref [2].
> 
> It was identified successful zero-day exploitation in the SharePoint systems
> of at least seven Union entities. But those incidents were not considered
> as severe incident because the Defender EDR blocked post-compromise attempts.
> Based on the current analysis and investigation there was not detected any
> leak of credentials used for post-exploitation activities.
> 
> At this moment Microsoft released new SharePoint patches to fix these
> vulnerabilities. Microsoft has released security updates that fully protect
> customers using all supported versions of SharePoint affected by these two
> vulnerabilities. For more information about patching review the customer
> guidance for SharePoint vulnerability ref [3],[4].   
> 



## 🖥️ Terrain 

 > Vulnerable SharePoint server allowing unauthenticated requests leading to
> remote code execution.  
> 

 &nbsp;
### ❤️‍🩹 Common Vulnerability Enumeration

⚠️ ERROR : Could not successfully retrieve CVE Details, double check the broken links below to confirm the CVE ID exists.

- [💔 CVE-2025-53770](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)
- [💔 CVE-2025-53771](https://nvd.nist.gov/vuln/detail/CVE-2025-53771)

&nbsp;

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Aliases                                                                                                                                                                                               | Source                     | Sighting                                                                                                                                                                                                                                                                                                                                                                                                    | Reference                                                                                                                         |
|:-------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------|
| [Enterprise] Threat Group-3390 | [Threat Group-3390](https://attack.mitre.org/groups/G0027) is a Chinese threat group that has extensively used strategic Web compromises to target victims.(Citation: Dell TG-3390) The group has been active since at least 2010 and has targeted organizations in the aerospace, government, defense, technology, energy, manufacturing and gambling/betting sectors.(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Securelist LuckyMouse June 2018)(Citation: Trend Micro DRBControl February 2020)                                                                                                                                                                                                                                   | APT27, BRONZE UNION, Earth Smilodon, Emissary Panda, Iron Tiger, LuckyMouse, TG-3390                                                                                                                  | 🗡️ MITRE ATT&CK Groups     | No documented sighting                                                                                                                                                                                                                                                                                                                                                                                      | No documented references                                                                                                          |
| APT27                          | A China-based actor that targets foreign embassies to collect data on government, defence, and technology sectors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | GreedyTaotie, TG-3390, EMISSARY PANDA, TEMP.Hippo, Red Phoenix, Budworm, Group 35, ZipToken, Iron Tiger, BRONZE UNION, Lucky Mouse, G0027, Iron Taurus, Earth Smilodon, Circle Typhoon, Linen Typhoon | 🌌 MISP Threat Actor Galaxy | Linen Typhoon (APT27) is linked threat actor to Ministry of StateSecurity (MSS) of the People's Republic of China. This threat actor isobserved to exploit SharePoint vulnerabilities since 2019. Since 2012, Linen Typhoon has focused on stealing intellectual property,primarily targeting organizations related to government, defense,strategic planning, and human rights ref [10].                   | https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities |
| [Enterprise] ZIRCONIUM         | [ZIRCONIUM](https://attack.mitre.org/groups/G0128) is a threat group operating out of China, active since at least 2017, that has targeted individuals associated with the 2020 US presidential election and prominent leaders in the international affairs community.(Citation: Microsoft Targeting Elections September 2020)(Citation: Check Point APT31 February 2021)                                                                                                                                                                                                                                                                                                                                                                          | APT31, Violet Typhoon                                                                                                                                                                                 | 🗡️ MITRE ATT&CK Groups     | No documented sighting                                                                                                                                                                                                                                                                                                                                                                                      | No documented references                                                                                                          |
| APT31                          | FireEye characterizes APT31 as an actor specialized on intellectual property theft, focusing on data and projects that make a particular organization competetive in its field. Based on available data (April 2016), FireEye assesses that APT31 conducts network operations at the behest of the Chinese Government. Also according to Crowdstrike, this adversary is suspected of continuing to target upstream providers (e.g., law firms and managed service providers) to support additional intrusions against high-profile assets. In 2018, CrowdStrike observed this adversary using spear-phishing, URL “web bugs” and scheduled tasks to automate credential harvesting.                                                                | ZIRCONIUM, JUDGMENT PANDA, BRONZE VINEWOOD, Red keres, Violet Typhoon, TA412, Zirconium                                                                                                               | 🌌 MISP Threat Actor Galaxy | A Chinese affiliated threat actor Violet Typhoon (APT31) exploitsSharePoint vulnerabilities and targets internet-facing SharePointservers. More details in ref [4].                                                                                                                                                                                                                                         | https://securityaffairs.com/180267/apt/microsoft-linked-attacks-on-sharepoint-flaws-to-china-nexus-actors.html                    |
| [Mobile] MoustachedBouncer     | [MoustachedBouncer](https://attack.mitre.org/groups/G1019) is a cyberespionage group that has been active since at least 2014 targeting foreign embassies in Belarus.(Citation: MoustachedBouncer ESET August 2023)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |                                                                                                                                                                                                       | 🗡️ MITRE ATT&CK Groups     | No documented sighting                                                                                                                                                                                                                                                                                                                                                                                      | No documented references                                                                                                          |
| Storm-2603                     | The group Microsoft tracks as Storm-2603 is assessed with medium confidence to be a China-based threat actor. Microsoft has not identified links between Storm-2603 and other known Chinese threat actors. Microsoft tracks this threat actor in association with attempts to steal MachineKeys via the on-premises SharePoint vulnerabilities. Although Microsoft has observed this threat actor deploying Warlock and Lockbit ransomware in the past, Microsoft is currently unable to confidently assess the threat actor’s objectives.  Additional actors may use these exploits to target unpatched on-premises SharePoint systems, further emphasizing the need for organizations to implement mitigations and security updates immediately. |                                                                                                                                                                                                       | 🌌 MISP Threat Actor Galaxy | Another China-based threat actor, tracked as Storm-2603, exploiting thesame SharePoint vulnerabilities to deploy ransomware. Storm-2603 initialaccess to the environment using the `spinstall0.aspx` payload. Thisinitial access is used to conduct command execution and then initiatesa series of discovery commands, including `whoami`, to enumerate usercontext and validate privilege levels ref [7]. | https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🏃🏽 Defense Evasion`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques an attacker may specifically use for evading detection or avoiding other defenses.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 Customer`](http://veriscommunity.net/enums.html#section-asset) : People - Customer
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - [` Microsoft SharePoint`](https://docs.microsoft.com/en-us/sharepoint/) : Microsoft SharePoint is a cloud-based service that helps organizations share and manage content, knowledge, and applications
 - ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🚨 Highly significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html
- [_2_] https://research.eye.security/sharepoint-under-siege
- [_3_] https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770
- [_4_] https://thehackernews.com/2025/07/microsoft-releases-urgent-patch-for.html
- [_5_] https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-sharepoint-enterprise-server-2016-july-8-2025-kb5002744-9196e240-c76d-4bb0-b16c-6f7d6645a1f0
- [_6_] https://securityaffairs.com/180267/apt/microsoft-linked-attacks-on-sharepoint-flaws-to-china-nexus-actors.html
- [_7_] https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities
- [_8_] https://thehackernews.com/2025/07/storm-2603-exploits-sharepoint-flaws-to.html
- [_9_] https://thehackernews.com/2025/07/microsoft-links-ongoing-sharepoint.html
- [_10_] https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities

[1]: https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html
[2]: https://research.eye.security/sharepoint-under-siege
[3]: https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770
[4]: https://thehackernews.com/2025/07/microsoft-releases-urgent-patch-for.html
[5]: https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-sharepoint-enterprise-server-2016-july-8-2025-kb5002744-9196e240-c76d-4bb0-b16c-6f7d6645a1f0
[6]: https://securityaffairs.com/180267/apt/microsoft-linked-attacks-on-sharepoint-flaws-to-china-nexus-actors.html
[7]: https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities
[8]: https://thehackernews.com/2025/07/storm-2603-exploits-sharepoint-flaws-to.html
[9]: https://thehackernews.com/2025/07/microsoft-links-ongoing-sharepoint.html
[10]: https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


