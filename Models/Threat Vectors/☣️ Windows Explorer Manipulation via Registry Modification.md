

# ☣️ Windows Explorer Manipulation via Registry Modification

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1112 : Modify Registry](https://attack.mitre.org/techniques/T1112 'Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and executionAcces'), [T1547.001 : Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key Adding an entry to the run keys ')



---

`🔑 UUID : 8e5c12f1-cd48-417c-a9c9-883212bf98b6` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-07-11` **|** `🗓️ Last Modification : 2025-07-16` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Explorer behaviour can be twisted by editing the registry keys
> listed below. Changes act instantly, leave few artefacts, and
> are often missed by file-centric defenses.
> 
> ### Policy Edits Disable User Defenses
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer  
> Setting `DisableTaskMgr`, `DisableRegistryTools`, `NoViewOnDrive` or
> NoFind stops Task Manager, Regedit, search and drive browsing,
> blinding users.
> Setting `NavPaneShowAllFolders` or `NavPaneExpandToCurrentFolder` can 
> modify the navigation pane.
> When set to 0, this value hides certain folders in the navigation pane, 
> such as system folders or folders that are not typically displayed,
> making it difficult for users to detect malicious activity.
> When set to 1, this value shows all folders in the navigation pane, 
> including hidden and system folders, making it harder for users to 
> distinguish between legitimate and malicious files or folders.
> 
> ### Advanced Flags Hide Artefacts
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
> Flipping Hidden, ShowSuperHidden or SuperHidden hides system
> files and payloads, thwarting GUI-based hunting.
> 
> ### User Shell Redirection
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
> Replacing Desktop, Startup or Personal paths diverts files or
> autoruns to attacker-controlled folders for theft or persistence.
> 
> ### System-Wide Folder Hijack
> - HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
> System-level redirection funnels all users' documents and
> shortcuts to rogue directories, enabling broad data capture.
> 
> ### Global Advanced Flags Override
> - HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
> Modifying the machine hive mirrors the HKCU tweaks but forces
> hidden-file suppression and other changes on every profile.
> 
> ### Environment Variable Hijack
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders  
> Altering %APPDATA%, %TEMP% or %DESKTOP% variables tricks apps
> into saving data or loading DLLs from malicious locations.
> 
> ### Namespace Injection
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace  
> Creating fake CLSID subkeys inserts rogue folders in Explorer,
> luring users to launch payloads masked as system objects.
> 
> ### Drive AutoRun Seeds
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2    
> Inserting AutoRun and command entries forces code execution
> whenever a specific USB or network share is browsed.
> 
> ### Default Shell Replacement
> - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell  
> Repointing the Shell value swaps explorer.exe for a malicious
> binary, gaining control each time a user signs in.
> 
> ### Enabling AutoPlay for Malicious Devices
> - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  
> Changing the `DeviceType` or `Handler` settings can enable AutoPlay for specific 
> devices, such as network shares, potentially executing malicious code.
> 



## 🖥️ Terrain 

 > Adversary must obtain write access to the user-hive (HKCU) or,
> for broader impact, administrative rights to HKLM and the
> ability to execute **reg.exe**, PowerShell, or equivalent APIs on
> Windows 7 - 11 workstations joined to Active Directory.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Aliases                                                                                          | Source                 | Sighting                                                   | Reference                                                                                                |
|:--------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------|:-----------------------|:-----------------------------------------------------------|:---------------------------------------------------------------------------------------------------------|
| [ICS] Wizard Spider | [Wizard Spider](https://attack.mitre.org/groups/G0102) is a Russia-based financially motivated threat group originally known for the creation and deployment of [TrickBot](https://attack.mitre.org/software/S0266) since at least 2016. [Wizard Spider](https://attack.mitre.org/groups/G0102) possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.(Citation: CrowdStrike Ryuk January 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: CrowdStrike Wizard Spider October 2020) | DEV-0193, FIN12, GOLD BLACKBURN, Grim Spider, ITG23, Periwinkle Tempest, TEMP.MixMaster, UNC1878 | 🗡️ MITRE ATT&CK Groups | Ryuk ransomware has targetted the associated registry keys | https://www.crowdstrike.com/en-us/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ |

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

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🛠️ Virtual Machines`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 Windows API`](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) : The Windows API, informally WinAPI, is Microsoft's core set of application programming interfaces (APIs) available in the Microsoft Windows operating systems. The name Windows API collectively refers to several different platform implementations that are often referred to by their own names (for example, Win32 API). Almost all Windows programs interact with the Windows API.

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Active Directory` : Placeholder
 - ` PowerShell` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`✨ Modify data`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify stored data or content
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html
- [_2_] https://vms.drweb.com/virus/?i=27670435
- [_3_] https://www.crowdstrike.com/en-us/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/

[1]: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html
[2]: https://vms.drweb.com/virus/?i=27670435
[3]: https://www.crowdstrike.com/en-us/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


