

# ☣️ Process discovery

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1057 : Process Discovery](https://attack.mitre.org/techniques/T1057 'Adversaries may attempt to get information about running processes on a system Information obtained could be used to gain an understanding of common s')



---

`🔑 UUID : cc7dd57f-8d9e-451f-8ec7-4bb2ad10e96c` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-02-04` **|** `🗓️ Last Modification : 2025-02-04` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> A process discovery refers to the process of identifying and analyzing
> the running processes on a system or network. This involves gathering
> information about the processes, such as their names, IDs, command
> lines, and other relevant details ref [1].  
> 
> For example, in Windows environment, an adversary could obtain details
> on running processes using the Tasklist utility via cmd or `Get-Process`
> via PowerShell. Information about processes can also be extracted from
> the output of Native API calls such as `CreateToolhelp32Snapshot`
> ref [2].  
> 
> In Mac and Linux, this is accomplished with the ps command.
> The threat actors may also opt to enumerate processes via /proc.
> 
> By analyzing the running processes on a system or network, the threat
> actors can abuse process discovery functionality in some of the
> following ways:  
> 
> ### Living-off-the-Land (LOTL) techniques to identify potential targets 
> 
> The threat actors may abuse native tools (PowerShell, WMIC) to blend
> in with normal activity, avoiding suspicion.    
> 
> ### Used tools by threat actors for process discovery on a target system
> 
> #### 1. Tasklist (Windows built-in) 
> 
> This command-line tool is used to display a list of currently running
> processes on a Windows system. Threat actors might use it to identify
> potential targets for exploitation or to understand the system's
> configuration.  
> 
> #### 2. Process Monitor (SysInternals)
> 
> Process Monitor can be used to verify if the browser or other service
> is launched on a target system and with what level of privileges. This
> tool can monitor what processes are running on the system.      
> 
> #### 3. PsExec (SysInternals) 
> 
> This tool allows users to execute processes remotely, but it can also
> be used to list running processes on a target system. Threat actors
> might use PsExec to gather information about the system's processes
> without being detected.
> 
> #### 4. PowerShell (Windows built-in)
> 
> PowerShell is a powerful scripting language that can be used to
> automate tasks, including process discovery. Threat actors might use
> PowerShell cmdlets like Get-Process to list running processes on a
> target system.  
> 
> #### 5. Windows Management Instrumentation functionality (Windows built-in)
> 
> Threat actors can abuse WMI (Windows Management Instrumentation) filters
> in Windows for process discovery. Examples include running WMI queries
> (e.g., WMIC) to retrieve information about running processes, Creating
> WMI specific event filters to monitor process creation, modification
> and other process related information. Threat actors also can utilize
> WMI filters to execute queries that retrieve process information,
> for example: such as `SELECT * FROM Win32_Process`.  
> 
> #### 6. ProcDump (SysInternals)
> 
> This tool is designed to capture and analyze process dumps, but it can
> also be used to list running processes on a target system. Threat actors
> might use ProcDump to gather information about the system's processes and
> identify potential vulnerabilities.  
> 
> #### 7. Process Explorer (SysInternals)
> 
> This tool provides a detailed view of running processes, including their
> memory usage, network connections, and system resources. Threat actors
> might use Process Explorer to gather information about the system's
> processes and identify potential targets for exploitation.  
> 
> #### 8. Cygwin or Linux tools (e.g., ps, top, htop)
> 
> If the target system has a Unix-like environment installed, threat actors
> might use tools like ps, top, or htop to list running processes and gather
> information about the system's configuration.  
> 
> #### 9. Meterpreter (Metasploit)
> 
> Meterpreter is a payload that can be used to exploit vulnerabilities and
> gain access to a target system. It includes a range of tools, including
> process discovery capabilities, that threat actors can use to gather
> information about the system's processes.
> 
> #### 10. Cobalt Strike's Process List
> 
> Cobalt Strike is a commercial penetration testing tool that includes
> a range of features, including process discovery. Threat actors might
> use Cobalt Strike to list running processes on a target system and
> identify potential targets for exploitation.
> 



## 🖥️ Terrain 

 > Threat actors rely on exposed / public visible processes,
> they can scan and gather information for a target.  
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🧭 Discovery`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques that allow an attacker to gain knowledge about a system and its network environment.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🔧 Embedded` : Firmware, middleware and low level software running on devices which are typically not manageable by the consumer.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`👤 Customer`](http://veriscommunity.net/enums.html#section-asset) : People - Customer
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Linux` : Placeholder
 - ` macOS` : Placeholder
 - ` PowerShell` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.
 - [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.
 - [`💲 Operating costs`](http://veriscommunity.net/enums.html#section-impact) : Increased operating costs
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://medium.com/@stackzero/how-to-do-process-enumeration-an-alternative-way-stackzero-fad874477cda
- [_2_] https://cyber-kill-chain.ch/techniques/T1057/
- [_3_] https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879

[1]: https://medium.com/@stackzero/how-to-do-process-enumeration-an-alternative-way-stackzero-fad874477cda
[2]: https://cyber-kill-chain.ch/techniques/T1057/
[3]: https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


