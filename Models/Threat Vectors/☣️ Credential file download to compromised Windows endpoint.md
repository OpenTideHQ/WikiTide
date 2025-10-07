

# ☣️ Credential file download to compromised Windows endpoint

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1552.001 : Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001 'Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials These can be files created by user'), [T1555.004 : Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004 'Adversaries may acquire credentials from the Windows Credential Manager The Credential Manager stores credentials for signing into websites, applicati')



---

`🔑 UUID : 94b7287b-ae84-4b89-8093-63898c7475c9` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-03-12` **|** `🗓️ Last Modification : 2025-03-12` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> A credential file download to Windows compromised endpoint
> refers to a process where an attacker downloads sensitive
> credential files to this system. A threat actor usually
> target to download files containing passwords, authentication
> tokens, or other sensitive information. Threat actors may use
> remote tools to download Windows credential files and to
> extract their content if its decrypted ref [1], [2].  
> 
> ### Methods used by the threat actors
> 
> Threat actors may use various methods to download credential files,
> for example:
> 
> - SMB (Server Message Block) exploitation: Attackers may exploit
> vulnerabilities in SMB to gain access to the compromised endpoint
> and download credential files.
> - PowerShell scripts: Attackers may use PowerShell scripts to
> download credential files from the compromised endpoint.
> - Remote Desktop Protocol (RDP): Attackers may use RDP to gain
> access to the compromised endpoint and download credential files.
> - Malware: Attackers may use malware to download credential files
> from the compromised endpoint.
> - Curl for Windows (via HTTP requests) - Adversaries could abuse
> `Curl` to download files or upload data to a remote URL address
> ref [2].  
> - Remote Desktop PassView - this tool can access Windows credential
> files via .rdp files. It's possible such file to contain user's
> credentials ref [3]. 
> 
> ### Known types of files which may contain user's credentials 
> 
> The following types of credential files may be downloaded by the
> attackers through a compromised network:
> 
> - SAM (Security Account Manager) files: These files contain hashed
> passwords for local user accounts.
> - NTDS.DIT files: These files contain hashed passwords for Active
> Directory user accounts.
> - Credential Manager files: These files contain stored credentials
> for applications and services.
> - SSH key files: These files contain private SSH keys used for
> authentication.  
> 
> ### An example 
> 
> Threat actors can download and use the accessed credential user's
> files to connect to a database further, without having to enter
> login credentials each time they access the database. The database
> system will authenticate their login based on the information
> stored in the credential file.   
> 



## 🖥️ Terrain 

 > Requires an already compromised Windows endpoint.  
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Aliases                                                                                                               | Source                     | Sighting               | Reference                                                                                                |
|:-----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:---------------------------------------------------------------------------------------------------------|
| [Enterprise] TA505     | [TA505](https://attack.mitre.org/groups/G0092) is a cyber criminal group that has been active since at least 2014. [TA505](https://attack.mitre.org/groups/G0092) is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving [Clop](https://attack.mitre.org/software/S0611).(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 June 2018)(Citation: Proofpoint TA505 Jan 2019)(Citation: NCC Group TA505)(Citation: Korean FSI TA505 2020)                                                                                                                                                                                                                                                                                                                                                                                  | CHIMBORAZO, Hive0065, Spandex Tempest                                                                                 | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references                                                                                 |
| TA505                  | TA505, the name given by Proofpoint, has been in the cybercrime business for at least four years. This is the group behind the infamous Dridex banking trojan and Locky ransomware, delivered through malicious email campaigns via Necurs botnet. Other malware associated with TA505 include Philadelphia and GlobeImposter ransomware families.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | SectorJ04, SectorJ04 Group, GRACEFUL SPIDER, GOLD TAHOE, Dudear, G0092, ATK103, Hive0065, CHIMBORAZO, Spandex Tempest | 🌌 MISP Threat Actor Galaxy | No documented sighting | https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta505-dridex-globeimposter        |
| [Enterprise] Leafminer | [Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Raspite                                                                                                               | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references                                                                                 |
| RASPITE                | Dragos has identified a new activity group targeting access operations in the electric utility sector. We call this activity group RASPITE.  Analysis of RASPITE tactics, techniques, and procedures (TTPs) indicate the group has been active in some form since early- to mid-2017. RASPITE targeting includes entities in the US, Middle East, Europe, and East Asia. Operations against electric utility organizations appear limited to the US at this time.  RASPITE leverages strategic website compromise to gain initial access to target networks. RASPITE uses the same methodology as DYMALLOY and ALLANITE in embedding a link to a resource to prompt an SMB connection, from which it harvests Windows credentials. The group then deploys install scripts for a malicious service to beacon back to RASPITE-controlled infrastructure, allowing the adversary to remotely access the victim machine. | LeafMiner, Raspite                                                                                                    | 🌌 MISP Threat Actor Galaxy | No documented sighting | https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east |
| [ICS] APT33            | [APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors.(Citation: FireEye APT33 Sept 2017)(Citation: FireEye APT33 Webinar Sept 2017)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Elfin, HOLMIUM, Peach Sandstorm                                                                                       | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references                                                                                 |
| APT33                  | Our analysis reveals that APT33 is a capable group that has carried out cyber espionage operations since at least 2013. We assess APT33 works at the behest of the Iranian government.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | APT 33, Elfin, MAGNALLIUM, Refined Kitten, HOLMIUM, COBALT TRINITY, G0064, ATK35, Peach Sandstorm, TA451              | 🌌 MISP Threat Actor Galaxy | No documented sighting | https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage                      |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔑 Credential Access`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques resulting in the access of, or control over, system, service or domain credentials.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🗄️ Production Database`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.
 - [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://blog.bitsadmin.com/extracting-credentials-from-remote-windows-system
- [_2_] https://www.elastic.co/guide/en/security/8.17/potential-file-transfer-via-curl-for-windows.html
- [_3_] https://www.nirsoft.net/utils/remote_desktop_password.html
- [_4_] https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details/
- [_5_] https://serverfault.com/questions/770996/where-does-credential-manager-store-credentials-on-the-file-system
- [_6_] https://www.proofpoint.com/us/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant
- [_7_] https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta505-dridex-globeimposter
- [_8_] https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage
- [_9_] https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east

[1]: https://blog.bitsadmin.com/extracting-credentials-from-remote-windows-system
[2]: https://www.elastic.co/guide/en/security/8.17/potential-file-transfer-via-curl-for-windows.html
[3]: https://www.nirsoft.net/utils/remote_desktop_password.html
[4]: https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details/
[5]: https://serverfault.com/questions/770996/where-does-credential-manager-store-credentials-on-the-file-system
[6]: https://www.proofpoint.com/us/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant
[7]: https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta505-dridex-globeimposter
[8]: https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage
[9]: https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


