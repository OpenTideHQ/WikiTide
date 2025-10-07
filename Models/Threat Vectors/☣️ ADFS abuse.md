

# ☣️ ADFS abuse

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1556 : Modify Authentication Process](https://attack.mitre.org/techniques/T1556 'Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts The authe'), [T1133 : External Remote Services](https://attack.mitre.org/techniques/T1133 'Adversaries may leverage external-facing remote services to initially access andor persist within a network Remote services such as VPNs, Citrix, and '), [T1606.002 : Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002 'An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificateCitation Microsoft ')



---

`🔑 UUID : 19a7a12e-1c7a-4885-9359-56abd63c85c9` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-06-24` **|** `🗓️ Last Modification : 2025-06-24` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> AD FS (Active Directory Federation Services) is a critical identity provider solution 
> for secure SSO authentication, but it presents a significant attack surface for 
> threat actors. Below is a comprehensive overview of ADFS abuse threat vectors, attack 
> techniques, and real-world exploitation patterns based on current research and incident data.
> 
> ### Memory Adapter Manipulation
> 
> Attackers with local administrative privileges on an AD FS server can modify AD 
> FS-related .NET assemblies or configuration files (such as those in the Global Assembly Cache). 
> By injecting malicious code or altering authentication logic in memory or on disk, 
> they can compromise the authentication process, potentially allowing unauthorised access.
> 
> ### Golden SAML Attacks
> 
> Attackers can steal or forge SAML tokens by accessing the AD FS token signing certificates. 
> With these certificates, they can create valid SAML tokens impersonating any user, 
> granting themselves unauthorised access to federated applications (such as Microsoft 365).
> 
> ### Phishing & MFA Bypass
> 
> Phishing campaigns specifically target AD FS users, tricking them into entering 
> credentials on fake login pages. Once credentials are harvested, attackers may intercept 
> Multi-Factor Authentication (MFA) codes or session cookies in real time, bypassing 
> MFA protections.
> 
> ### Information Disclosure via Vulnerabilities
>   
> Historical vulnerabilities (like CVE-2017-0043) have allowed authenticated attackers 
> to read sensitive information from AD FS servers via crafted XML requests. While 
> many such vulnerabilities are patched, they highlight the risk of information leakage.
> 
> ### Credential Reuse and Lateral Movement
> 
> Attackers who obtain AD FS credentials often find that these credentials are reused 
> across other systems or SSO platforms. This allows them to move laterally within 
> the victim’s environment, accessing multiple services.
> 



## 🖥️ Terrain 

 > Threat actors can obtain the token signing certificate and private key by abusing 
> the Policy Store Transfer Service to extract the encrypted certificate, then decrypting 
> it using the DKM key from Active Directory. This can be done remotely if the attacker 
> has the right privileges, and once they have the private key, they can forge SAML 
> tokens for any user, bypassing authentication controls.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `🕸️ SaaS` : Subscription based access to software.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`👤 Identity Services`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🛡️ SAML-Joined Applications`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🪣 Cloud Storage Accounts`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🔑 Server Authentication`](http://veriscommunity.net/enums.html#section-asset) : Server - Authentication

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` AD FS` : Placeholder
 - ` Active Directory` : Placeholder
 - ` Azure AD` : Placeholder
 - ` Office 365` : Placeholder
 - ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`🗿 Repudiation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at performing prohibited operations in a system that lacks the ability to trace the operations.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.hunters.security/en/blog/adfs-threat-hunting
- [_2_] https://www.beyondidentity.com/resource/active-microsoft-adfs-phishing-campaign-bypasses-mfa
- [_3_] https://www.itpro.com/operating-systems/microsoft-windows/359365/hackers-could-abuse-legitimate-windows-ad-fs-to-steal

[1]: https://www.hunters.security/en/blog/adfs-threat-hunting
[2]: https://www.beyondidentity.com/resource/active-microsoft-adfs-phishing-campaign-bypasses-mfa
[3]: https://www.itpro.com/operating-systems/microsoft-windows/359365/hackers-could-abuse-legitimate-windows-ad-fs-to-steal

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


