

# ☣️ Windows system links used for file redirection attack

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1562 : Impair Defenses](https://attack.mitre.org/techniques/T1562 'Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms This not only involves impair'), [T1027.012 : Obfuscated Files or Information: LNK Icon Smuggling](https://attack.mitre.org/techniques/T1027/012 'Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign windows shortcut')



---

`🔑 UUID : 9fc6fdcd-c06e-4f7b-8562-a6753d8be683` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2024-04-24` **|** `🗓️ Last Modification : 2024-06-25` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> By using different types of file system links, such as hard links or junctions, 
> attackers can trick the privileged component into operating on files which is 
> not supposed to access. The end goal for such attacks is usually to write an 
> attacker-supplied executable (such as a DLL or a script) to the disk, 
> and to get it executed with system permissions (ref \[1\]).  
> 
> For example, to achieve code execution as the SYSTEM user, threat actors start 
> an orchestrator update service, which will result in a malicious DLL being run 
> with SYSTEM privileges due to a DLL hijacking issue within the Update Session 
> Orchestrator Service. (ref \[2\])  
> 
> The most common file redirection links are:
> 
> ##### LNK files (shortcut files)
> 
> These are files with the .LNK extension, which are used to create shortcuts to 
> other files or folders. Attackers can exploit LNK files to execute malicious 
> code by creating a shortcut that points to a malicious file instead of the original 
> intended target.  
> 
> ##### Junction points
> 
> Junction points are special folders in Windows that link to another folder, allowing 
> the operating system to treat the content of the target folder as if they were 
> located in the junction point's folder. Attackers can use junction points to redirect 
> file access to a different location, potentially allowing them to access or modify 
> files that should not be accessible.  
> 
> Junctions are a feature of the NT file system (NTFS) that make it possible to link one 
> directory into another. They are used by default, linking some directories such as 
> "C:\\Documents and Settings".  
> 
> A common vulnerable pattern may exist in the hard (junction) links as follows 
> (for example CVE-2020-0787):
> 
> * A privileged service exposes functionality that can be triggered through some 
> interprocess communication (IPC) mechanism, such as remote procedure call (RPC). 
> That functionality can be triggered by users running at lower privilege levels.  
> * That functionality operates on a file (writing data into that file) that is 
> located under a globally writable directory. The operation is done without 
> impersonation, meaning it occurs with the permissions of that system service.  
> 
> To exploit this vulnerability in the system links a threat actor first creates a junction 
> between that directory and their target, which is usually C:\\Windows or one of its 
> subdirectories. Next, the attacker triggers the RPC call, which follows the junction to 
> overwrite a system DLL file. Finally, that malicious DLL is loaded by some service, 
> and the attacker's supplied code gets executed with system permissions (ref \[1\]).  
> 
> ##### Symbolic links:
> 
> Symbolic links (also known as symlinks or soft links) are similar to junction points, 
> but they can link to individual files as well as folders. Symbolic links can be used to 
> redirect file access to a different file or folder, which may allow an attacker to 
> execute malicious code or access sensitive information.  
> 
> ##### NTFS Alternate Data Streams (ADS):
> 
> Alternate Data Streams are a feature of the NTFS file system that allows storing 
> metadata within a file. Attackers can abuse ADS to hide malicious code or sensitive 
> information within an innocent-looking file. When the file is accessed, the malicious 
> content in the ADS is executed without the user's knowledge.  
> 



## 🖥️ Terrain 

 > A threat actor needs an initial access to the system with 
> standard user rights.
> 

 &nbsp;
### ❤️‍🩹 Common Vulnerability Enumeration

⚠️ ERROR : Could not successfully retrieve CVE Details, double check the broken links below to confirm the CVE ID exists.

- [💔 CVE-2020-0787](https://nvd.nist.gov/vuln/detail/CVE-2020-0787)

&nbsp;

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

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`📂 Directory`](http://veriscommunity.net/enums.html#section-asset) : Server - Directory (LDAP, AD)
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Azure AD` : Placeholder
 - ` Active Directory` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🔫 Localised incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`♻️ Environment dependent`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Depends

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/
- [_2_] https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0787_bits_arbitrary_file_move.rb
- [_3_] https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0787/

[1]: https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/
[2]: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0787_bits_arbitrary_file_move.rb
[3]: https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0787/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


