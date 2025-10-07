

# ☣️ Paragon Spyware

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1430 : Mobile : Location Tracking](https://attack.mitre.org/techniques/T1430 'Adversaries may track a devices physical location through use of standard operating system APIs via malicious or exploited applications on the comprom'), [T1636.003 : Mobile : Contact List](https://attack.mitre.org/techniques/T1636/003 'Adversaries may utilize standard operating system APIs to gather contact list data On Android, this can be accomplished using the Contacts Content Pro'), [T1189 : Drive-by Compromise](https://attack.mitre.org/techniques/T1189 'Adversaries may gain access to a system through a user visiting a website over the normal course of browsing Multiple ways of delivering exploit code '), [T1513 : Mobile : Screen Capture](https://attack.mitre.org/techniques/T1513 'Adversaries may use screen capture to collect additional information about a target device, such as applications running in the foreground, user data,'), [T1633 : Mobile : Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633 'Adversaries may employ various means to detect and avoid virtualization and analysis environments This may include changing behaviors after checking f'), [T1068 : Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges Exploitation of a software vulnerability occurs when an adversary')



---

`🔑 UUID : e1741a76-3df1-430a-8dda-5c6bc9c3e1dd` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-03-26` **|** `🗓️ Last Modification : 2025-03-26` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Paragon Spyware, also known as Graphite, is a sophisticated surveillance tool developed 
> by Paragon Solutions, an Israeli company founded in 2019. This spyware is designed to infiltrate 
> encrypted messaging apps such as WhatsApp, Signal, Facebook Messenger, and Gmail, allowing 
> law enforcement and intelligence agencies to intercept private communications.    
> 
> ## Key Features    
> 
> - **Zero-Click Exploit**: Graphite uses a "zero-click" method, meaning it can infect 
> a device without any action from the target.
> - **WhatsApp Vulnerability**: The spyware exploits a vulnerability in WhatsApp, 
> using a malicious PDF file to gain access to the device.
> - **Data Extraction**: Once installed, Graphite can extract stored files, photos, 
> and monitor communications across various platforms.
> - **Cloud Upload**: The extracted data is uploaded to a cloud server, leaving no 
> traces on the infected device.
> - **Sandbox Escape**: The spyware can escape the Android sandbox to compromise other 
> apps on the targeted devices.    
> 
> ## Recent Developments    
> 
> In January 2025, WhatsApp patched a zero-day vulnerability that was being exploited 
> by Paragon Spyware. The company notified approximately 90 Android users from over 
> 20 countries who were targeted, including journalists and activists.
> 



## 🖥️ Terrain 

 > Attackers add targets to a WhatsApp group and send a PDF file. When the device automatically 
> processes the PDF, it exploits a vulnerability to load the Graphite spyware
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔐 Persistence`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Any access, action or change to a system that gives an attacker persistent presence on the system.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `📱 Mobile` : Smartphones, tablets and applications running these devices.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`📱 Mobile phone`](http://veriscommunity.net/enums.html#section-asset) : User Device - Mobile phone or smartphone
 - [`🪪 Personal Information`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`📱 Tablet`](http://veriscommunity.net/enums.html#section-asset) : User Device - Tablet
 - [`👤 Identity Services`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` iOS` : Placeholder
 - ` Android` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`📉 Competitive disadvantage`](http://veriscommunity.net/enums.html#section-impact) : Loss of competitive advantage
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

- [_1_] https://www.bleepingcomputer.com/news/security/whatsapp-patched-zero-day-flaw-used-in-paragon-spyware-attacks/
- [_2_] https://www.schneier.com/blog/archives/2025/03/report-on-paragon-spyware.html
- [_3_] https://www.ynetnews.com/business/article/ryc4uibikl
- [_4_] https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/

[1]: https://www.bleepingcomputer.com/news/security/whatsapp-patched-zero-day-flaw-used-in-paragon-spyware-attacks/
[2]: https://www.schneier.com/blog/archives/2025/03/report-on-paragon-spyware.html
[3]: https://www.ynetnews.com/business/article/ryc4uibikl
[4]: https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


