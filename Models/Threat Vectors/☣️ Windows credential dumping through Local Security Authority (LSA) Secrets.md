

# ☣️ Windows credential dumping through Local Security Authority (LSA) Secrets

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1003 : OS Credential Dumping](https://attack.mitre.org/techniques/T1003 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password C'), [T1003.004 : OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004 'Adversaries with SYSTEM access to a host may attempt to access Local Security Authority LSA secrets, which can contain a variety of different credenti')



---

`🔑 UUID : 444e014f-d830-4d0d-9c2e-1f76d80ba380` **|** `🏷️ Version : 2` **|** `🗓️ Creation Date : 2022-11-04` **|** `🗓️ Last Modification : 2025-10-01` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Adversaries may attempt to dump credentials to obtain account login
> and credentials details, using techniques for Local Security Authority 
> (LSA) Secrets dumping. If the attacker has a System access to the host 
> this may lead to access LSA secrets database. Local Security Authority
> contains credential information related to local and domain based accounts. 
> The Registry is used to store the LSA secrets. When services are run under 
> the context of local or domain users, their passwords are stored in the 
> Registry at HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. If auto-logon is 
> enabled, this information will be stored in the Registry as well. 
> The extracted passwords are UTF-16 encoded, which means that they 
> are returned in plaintext. LSA secrets can also be dumped from memory.
> 
> Known tools used for LSA credential dumping:
> 
> - pwdumpx.exe
> - gsecdump
> - Mimikatz
> - secretsdump.py
> - reg.exe (execution file extracts information from the Registry)
> - Creddump7 (for gathering of credentials)
> 
> Executed commands and arguments that may access to a host may attempt to 
> access Local Security Authority (LSA) secrets. Remote access tools may contain 
> built-in features or incorporate existing tools like Mimikatz. PowerShell scripts
> also can contain credential LSA dumping functionality.



## 🖥️ Terrain 

 > Threat actor is searching entry points in the network to 
> gain system level access and registry access. This access 
> can be used for dumping information from LSA database and 
> further lateral movement in the environment.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





 --- 

### ⛓️ Threat Chaining

```mermaid

flowchart LR

09b9aee8-3849-4578-8243-17157d6d54e0[Windows credential creation attempt]
444e014f-d830-4d0d-9c2e-1f76d80ba380[Windows credential dumping through Local Security Authority LSA Secrets]

subgraph Credential Access
09b9aee8-3849-4578-8243-17157d6d54e0
444e014f-d830-4d0d-9c2e-1f76d80ba380
end

Windows[(Windows)]
WIZARDSPIDER{{WIZARD SPIDER}}
WizardSpider{{Wizard Spider}}
LAPSUS{{LAPSUS}}
LAPSUS${{LAPSUS$}}

09b9aee8-3849-4578-8243-17157d6d54e0 -.->|targets| Windows
444e014f-d830-4d0d-9c2e-1f76d80ba380 -.->|targets| Windows
WIZARDSPIDER -.-> |performs| 09b9aee8-3849-4578-8243-17157d6d54e0
WizardSpider -.-> |performs| 09b9aee8-3849-4578-8243-17157d6d54e0
LAPSUS -.-> |performs| 09b9aee8-3849-4578-8243-17157d6d54e0
LAPSUS$ -.-> |performs| 09b9aee8-3849-4578-8243-17157d6d54e0

09b9aee8-3849-4578-8243-17157d6d54e0 -->|succeeds| 444e014f-d830-4d0d-9c2e-1f76d80ba380

```


<details>
<summary>Expand chaining data</summary>

| ☣️ Vector                                                                                                                                                                                                                                                                | ⛓️ Link              | 🎯 Target                                                                                                                                                                                                                                                                                                                                                       | ⛰️ Terrain                                                                                                                                                                                                                   | 🗡️ ATT&CK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Windows credential creation attempt](../Threat%20Vectors/☣️%20Windows%20credential%20creation%20attempt.md '### Windows Credential Creation AttemptA Windows credential creation attempt refers to activities where a user or system processes aim to create, stor...') | `sequence::succeeds` | [Windows credential dumping through Local Security Authority (LSA) Secrets](../Threat%20Vectors/☣️%20Windows%20credential%20dumping%20through%20Local%20Security%20Authority%20(LSA)%20Secrets.md 'Adversaries may attempt to dump credentials to obtain account loginand credentials details, using techniques for Local Security Authority LSA Secrets ...') | Threat actor is searching entry points in the network to  gain system level access and registry access. This access  can be used for dumping information from LSA database and  further lateral movement in the environment. | [T1003 : OS Credential Dumping](https://attack.mitre.org/techniques/T1003 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password C'), [T1003.004 : OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004 'Adversaries with SYSTEM access to a host may attempt to access Local Security Authority LSA secrets, which can contain a variety of different credenti') |

</details>
&nbsp; 


---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔑 Credential Access`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques resulting in the access of, or control over, system, service or domain credentials.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🪪 Personal Information`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
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

- [_1_] https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
- [_2_] https://attack.mitre.org/software/S0075/

[1]: https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
[2]: https://attack.mitre.org/software/S0075/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


