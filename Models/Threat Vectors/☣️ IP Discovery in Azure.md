

# ☣️ IP Discovery in Azure

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1078 : Valid Accounts](https://attack.mitre.org/techniques/T1078 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense '), [T1526 : Cloud Service Discovery](https://attack.mitre.org/techniques/T1526 'An adversary may attempt to enumerate the cloud services running on a system after gaining access These methods can differ from platform-as-a-service '), [T1528 : Steal Application Access Token](https://attack.mitre.org/techniques/T1528 'Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resourcesApplication access tokens ar')



---

`🔑 UUID : 777e22c5-e47d-42a2-a803-42a101dee575` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-07-30` **|** `🗓️ Last Modification : 2025-08-04` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> IP Discovery in the context of Azure refers to an adversary’s technique for identifying 
> the public IP addresses associated with Azure resources. This activity is classified 
> in the Azure Threat Research Matrix (ATRM) under **reconnaissance** tactics, because 
> it is often one of the first steps attackers perform to understand the accessible 
> surface of a target Azure environment.
> 
> #### Attack Flow and Methodology
> 
> 1. **Initial Reconnaissance**  (see terrain)
>   The attacker needs valid credentials or otherwise access to an Azure environment 
>   
> 2. **Enumerating Resources**  
>   Using the Azure Portal, the Azure CLI, PowerShell, or Azure REST APIs, they enumerate 
>   resources—especially focusing on Virtual Machines (VMs) and Network Interfaces (NICs).
> 
> 3. **Querying for IP Information**  
>   The attacker issues read requests (such as `az network nic list`, `Get-AzNetworkInterface`, 
>   or relevant API calls) to retrieve detailed information about NICs. Each NIC 
>   object includes properties for associated public and private IP addresses.
> 
> 4. **Mapping IPs to VMs**  
>   From the NIC information, the adversary can link public IPs back to specific 
>   VMs or other endpoints, thereby building a map of accessible resources and potential 
>   entry points.
> 
> #### Attack Goals and Impact
> 
> - **Surface Mapping:** Generate a list of exposed public IP addresses and their 
> associated Azure resources.
> - **Prioritizing Targets:** Identify potentially vulnerable endpoints for direct 
> attack (RDP, SSH, web services) or for scanning later.
> - **Avoiding Detection:** Reconnaissance is “low and slow”—often blends in with 
> administrative activity, making detection challenging unless closely monitored.
> 
> #### Example Attack Scenario
> 
> 1. **Enumeration:**  
>   ```
>   az network nic list --query "[].{Name:name, IP:ipConfigurations[].publicIpAddress.id}"
>   ```
>   Or use the Azure REST API to enumerate all NICs and their attached public IPs.
> 
> 2. **Data Correlation:**  
>   Map discovered IPs to VMs using the relationships expressed in the Azure resource objects.
> 
> 3. **Follow-Up:**  
>   The attacker now has a list of direct IPs to probe for vulnerabilities 
>   (e.g., open RDP or SSH ports, misconfigured firewalls).
> 



## 🖥️ Terrain 

 > Adversary must have access to an Azure environment, either through compromised
> credentials, exposed keys, or abused privileges, and be able to use Azure Portal,
> Azure CLI, PowerShell, or Azure REST APIs.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔭 Reconnaissance`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Researching, identifying and selecting targets using active or passive reconnaissance.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🛠️ Virtual Machines`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🪣 Cloud Storage Accounts`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`☁️ Cloud Portal`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Azure` : Placeholder
 - ` Azure AD` : Placeholder
 - ` PowerShell` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://microsoft.github.io/Azure-Threat-Research-Matrix/Reconnaissance/AZT102/AZT102/

[1]: https://microsoft.github.io/Azure-Threat-Research-Matrix/Reconnaissance/AZT102/AZT102/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


