

# ☣️ OneDrive API abuse to exfiltrate sensitive data

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1190 : Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network The weakness in the system can be a s'), [T1534 : Internal Spearphishing](https://attack.mitre.org/techniques/T1534 'After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional ')



---

`🔑 UUID : 10663f4a-6432-4c8f-bd3a-eaa599bb474e` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-06-25` **|** `🗓️ Last Modification : 2025-06-25` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> OneDrive API abuse to exfiltrate sensitive data occurs when attackers misuse legitimate 
> Microsoft Graph API endpoints and OneDrive’s cloud storage features to steal confidential 
> or sensitive information from an organization.
> 
> ### How Does It Work?
> 
> 1. **API Exploitation via Microsoft Graph**
>   - Attackers use the Microsoft Graph API to access users’ OneDrive storage.
>   - Common endpoints include:
>     - `https://graph.microsoft.com/v1.0/users/{id}/drive` (to list drives)
>     - `https://graph.microsoft.com/v1.0/drive/items/{item-id}/content` (to download files)
>   - These APIs are normally used for legitimate cloud storage operations.
> 
> 2. **OAuth and Application Permissions**
>   - Attackers may compromise existing OAuth applications or create new ones.
>   - By granting these applications broad permissions (like “Files.Read.All” or 
>   “Files.ReadWrite.All”), attackers gain access to OneDrive files without direct 
>   user interaction.
> 
> 3. **Use of Trusted Cloud Services**
>   - Data exfiltration is carried out through OneDrive, a trusted and widely used 
>   cloud service.
>   - This makes malicious activity harder to distinguish from normal business operations.
> 
> 4. **Automated Exfiltration**
>   - Attackers often use scripts or malware to automate the process of accessing 
>   and transferring files via OneDrive.
>   - This allows for large-scale, stealthy data theft.
> 
> ### Attack Scenarios
> 
> - **Compromised Credentials:** An attacker gains access to an account with OneDrive 
> API permissions.
> - **Malicious OAuth App:** An attacker registers an OAuth app with excessive permissions 
> and uses it to access OneDrive files.
> - **Automated Scripts:** Attackers use PowerShell or other scripting tools to interact 
> with the OneDrive API, extracting sensitive files at scale.
> 



## 🖥️ Terrain 

 > Adversaries need an authenticated user or application identity (such as a compromised 
> user account or a maliciously registered OAuth application) with the necessary permissions 
> to access OneDrive files. And also, API permissions (like “Files.Read.All” or “Files.ReadWrite.All”) 
> that allow reading or downloading files from OneDrive via the Microsoft Graph API.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `🕸️ SaaS` : Subscription based access to software.
 - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🪣 Cloud Storage Accounts`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🪪 Personal Information`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🗄️ Production Database`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 Identity Services`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 API Endpoints`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`☁️ Cloud Portal`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Office 365` : Placeholder
 - ` Azure AD` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.paloaltonetworks.com/blog/security-operations/detecting-threats-with-microsoft-graph-activity-logs/
- [_2_] https://www.scworld.com/news/embargo-lifts-6-am-eastern-august-7-symantec-points-to-rise-in-attacks-on-cloud-infrastructure

[1]: https://www.paloaltonetworks.com/blog/security-operations/detecting-threats-with-microsoft-graph-activity-logs/
[2]: https://www.scworld.com/news/embargo-lifts-6-am-eastern-august-7-symantec-points-to-rise-in-attacks-on-cloud-infrastructure

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


