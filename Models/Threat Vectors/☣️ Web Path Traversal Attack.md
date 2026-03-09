

# ☣️ Web Path Traversal Attack

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1083 : File and Directory Discovery](https://attack.mitre.org/techniques/T1083 'Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file s')



---

`🔑 UUID : b330d3a8-1783-4210-9fec-11e6ecfe135e` **|** `🏷️ Version : 2` **|** `🗓️ Creation Date : 2022-09-01` **|** `🗓️ Last Modification : 2025-10-01` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Directory traversal (also known as file path traversal) is a web security
> vulnerability that allows an attacker to read arbitrary files on the server
> that is running an application. 
> 
> By manipulating variables that reference files with “dot-dot-slash (../)”
> sequences and its variations or by using absolute file paths, it may be
> possible to access arbitrary files and directories stored on file system
> including application source code or configuration and critical system files.
> 



## 🖥️ Terrain 

 > A web application vulnerable to path traversal, i.e. which does not
> sanitize user inputs sufficiently and with unsufficient resource access
> policy.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





 --- 

### ⛓️ Threat Chaining

```mermaid

flowchart LR

d15bff6c-b902-4975-ad3a-7a18f3026aca[Hide Artifacts using NTFS File Attributes]
b330d3a8-1783-4210-9fec-11e6ecfe135e[Web Path Traversal Attack]

subgraph Defense Evasion
d15bff6c-b902-4975-ad3a-7a18f3026aca
end
subgraph Discovery
b330d3a8-1783-4210-9fec-11e6ecfe135e
end

CVE-2025-8088>CVE-2025-8088]
APT28{{APT28}}
RomCom{{RomCom}}

d15bff6c-b902-4975-ad3a-7a18f3026aca -.->|exploits| CVE-2025-8088
APT28 -.-> |performs| d15bff6c-b902-4975-ad3a-7a18f3026aca
RomCom -.-> |performs| d15bff6c-b902-4975-ad3a-7a18f3026aca

d15bff6c-b902-4975-ad3a-7a18f3026aca -->|implements| b330d3a8-1783-4210-9fec-11e6ecfe135e

```


<details>
<summary>Expand chaining data</summary>

| ☣️ Vector                                                                                                                                                                                                                                                                                | ⛓️ Link                 | 🎯 Target                                                                                                                                                                                                                                             | ⛰️ Terrain                                                                                                                                          | 🗡️ ATT&CK                                                                                                                                                                                                                                  |
|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Hide Artifacts using NTFS File Attributes](../Threat%20Vectors/☣️%20Hide%20Artifacts%20using%20NTFS%20File%20Attributes.md 'Threat actors are using a hiding technique to conceal malicious files,folders, or other artifacts on a Windows system by leveraging the attributesof t...') | `atomicity::implements` | [Web Path Traversal Attack](../Threat%20Vectors/☣️%20Web%20Path%20Traversal%20Attack.md 'Directory traversal also known as file path traversal is a web securityvulnerability that allows an attacker to read arbitrary files on the serverthat...') | A web application vulnerable to path traversal, i.e. which does not sanitize user inputs sufficiently and with unsufficient resource access policy. | [T1083 : File and Directory Discovery](https://attack.mitre.org/techniques/T1083 'Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file s') |

</details>
&nbsp; 


---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🧭 Discovery`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques that allow an attacker to gain knowledge about a system and its network environment.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `🌐 Networking` : Communications backbone connecting users, applications and machines.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Linux` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`✨ Modify data`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify stored data or content

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://owasp.org/www-community/attacks/Path_Traversal
- [_2_] https://portswigger.net/web-security/file-path-traversal

[1]: https://owasp.org/www-community/attacks/Path_Traversal
[2]: https://portswigger.net/web-security/file-path-traversal

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


