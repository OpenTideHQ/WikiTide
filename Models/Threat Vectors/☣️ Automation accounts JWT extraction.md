

# ☣️ Automation accounts JWT extraction

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1134 : Access Token Manipulation](https://attack.mitre.org/techniques/T1134 'Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls Window'), [T1528 : Steal Application Access Token](https://attack.mitre.org/techniques/T1528 'Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resourcesApplication access tokens ar'), [T1550.001 : Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001 'Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or serv'), [T1190 : Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network The weakness in the system can be a s')



---

`🔑 UUID : 841e2a63-c95f-43f8-aef0-7ab96456445a` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-06-18` **|** `🗓️ Last Modification : 2025-06-18` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> The threat vector refers to attacks where attackers exploit Azure Automation Accounts 
> to steal JSON Web Tokens (JWTs) associated with Managed Identities, enabling privilege 
> escalation and lateral movement in cloud environments. Here's a detailed breakdown:
> 
> ## Attack Methodology
> **JWT Extraction via Runbook Modification**  
> Attackers modify Automation Account runbooks to execute PowerShell scripts that 
> access the Managed Identity endpoint:  
> ```powershell
> $tokenAuthURI = $env:MSI_ENDPOINT + "?resource=https://graph.microsoft.com/&api-version=2017-09-01"
> $tokenResponse = Invive-RestMethod -Method Get -Headers @{"Secret"="$env:MSI_SECRET"} -Uri $tokenAuthURI
> $tokenResponse.access_token
> ```
> This script retrieves a JWT for the Automation Account's Service Principal, which 
> attackers then exfiltrate.
> 
> ## Abuse Potential
> - **Privilege Escalation**: Stolen JWTs grant the same permissions as the Automation 
> Account's Managed Identity, enabling access to Azure Graph API, Key Vaults, and 
> other services.
> - **Token Replay**: Attackers use extracted JWTs to authenticate as the Service 
> Principal outside Azure Automation's context.
> - **Algorithm Confusion**: Weak JWT validation could allow attackers to modify token 
> claims while maintaining valid signatures (e.g., switching from RS256 to HS256).
> 
> ## Tooling
> - **JWTXposer**: Scans archives for leaked JWTs and analyzes claims for privilege 
> escalation opportunities.
> - **jwt_tool**: Performs dictionary attacks against JWT secrets and exploits algorithm 
> confusion vulnerabilities.
> - **Azure APIs**: Native tools like Az PowerShell modules can abuse valid JWTs for 
> resource enumeration.
> 



## 🖥️ Terrain 

 > Adversaries need to gain access to a valid JWT (JSON Web Token) associated with 
> the automation account’s managed identity. This access is typically achieved by 
> modifying automation runbooks or exploiting misconfigured permissions to execute 
> code that retrieves the JWT from the managed identity endpoint.
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
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🪣 Cloud Storage Accounts`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🗝️ Key Store`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 Identity Services`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Compute Cluster`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 API Endpoints`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
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

  - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a
- [_2_] https://em360tech.com/tech-articles/jwt-just-wait-til-it-breaks-common-token-mistakes-and-how-avoid-them
- [_3_] https://github.com/nearform/fast-jwt/security/advisories/GHSA-c2ff-88x2-x9pg

[1]: https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a
[2]: https://em360tech.com/tech-articles/jwt-just-wait-til-it-breaks-common-token-mistakes-and-how-avoid-them
[3]: https://github.com/nearform/fast-jwt/security/advisories/GHSA-c2ff-88x2-x9pg

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


