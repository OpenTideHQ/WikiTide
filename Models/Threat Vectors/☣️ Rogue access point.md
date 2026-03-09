

# ☣️ Rogue access point

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T0860 : Industrial : Wireless Compromise](https://attack.mitre.org/techniques/T0860 'Adversaries may perform wireless compromise as a method of gaining communications and unauthorized access to a wireless network Access to a wireless n'), [T1422.002 : Mobile : Wi-Fi Discovery](https://attack.mitre.org/techniques/T1422/002 'Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems Adversaries may use Wi-Fi inf'), [T1638 : Mobile : Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638 'Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors such as Transmitted Data Manipulat'), [T1557.004 : Adversary-in-the-Middle: Evil Twin](https://attack.mitre.org/techniques/T1557/004 'Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on beh')



---

`🔑 UUID : bdb9fd43-a9f9-4026-84a5-0b52d3b0243b` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-04-24` **|** `🗓️ Last Modification : 2025-04-24` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> A rogue access point (AP) is any wireless access point connected to a network without 
> explicit authorization from network administrators. These unauthorized devices 
> can be set up deliberately by attackers or unintentionally by employees, and they 
> bypass the security controls and configurations established by IT teams, exposing 
> the network to significant risks.
> 
> ### How Rogue Access Points Work
> 
> - **Impersonation:** Rogue APs may mimic legitimate networks by copying the Service 
> Set Identifier (SSID), tricking users into connecting to them.
> - **Open Access:** Many operate without passwords or encryption, making them easy 
> for devices to discover and connect to, but extremely vulnerable.
> - **Traffic Interception:** Once connected, attackers can intercept all data transmitted, 
> including credentials and confidential information, using packet sniffing tools.
> - **Attack Platform:** They serve as a launchpad for further attacks such as man-in-the-middle (MitM), 
> malware distribution, phishing, and ransomware deployment.
> 
> ### Risks and Threats
> 
> - **Data Interception & Theft:** Sensitive information, such as login credentials, 
> financial data, and confidential documents, can be captured.
> - **Man-in-the-Middle Attacks:** Attackers can intercept, modify, or inject data 
> into communications, hijack sessions, and steal credentials.
> - **Malware Distribution:** Rogue APs can be used to distribute malware or ransomware 
> to connected devices.
> - **Credential Theft:** Users may unknowingly submit credentials to attackers.
> - **Network Disruption:** Rogue APs can interfere with legitimate network operations, 
> causing downtime and instability.
> - **Regulatory Compliance Violations:** Industries with strict data regulations 
> (e.g., healthcare, finance) risk non-compliance and potential fines if rogue APs are present.
> 



## 🖥️ Terrain 

 > Adversaries must be within range of the target network to deploy or broadcast their 
> rogue AP. This could mean physical access to the premises (to connect a device to 
> the wired network) or being close enough to broadcast a Wi-Fi signal that clients 
> can detect and join.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🗃️ Collection`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques used to identify and gather data from a target network prior to exfiltration.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `📱 Mobile` : Smartphones, tablets and applications running these devices.
 - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`📱 Mobile phone`](http://veriscommunity.net/enums.html#section-asset) : User Device - Mobile phone or smartphone
 - [`📱 Tablet`](http://veriscommunity.net/enums.html#section-asset) : User Device - Tablet
 - [`🌐 Router or switch`](http://veriscommunity.net/enums.html#section-asset) : Network - Router or switch
 - [`🪪 Personal Information`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🗃️ Critical Documents`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` macOS` : Placeholder
 - ` Windows` : Placeholder
 - ` Linux` : Placeholder
 - ` Android` : Placeholder
 - ` iOS` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`📉 Competitive disadvantage`](http://veriscommunity.net/enums.html#section-impact) : Loss of competitive advantage
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.verimatrix.com/cybersecurity/knowledge-base/rogue-access-points-what-they-are-and-how-to-stop-them/
- [_2_] https://www.accessagility.com/rogue-wifi-wireless-access-point-ap
- [_3_] https://zimperium.com/glossary/rogue-access-point/
- [_4_] https://jumpcloud.com/it-index/what-is-a-rogue-access-point

[1]: https://www.verimatrix.com/cybersecurity/knowledge-base/rogue-access-points-what-they-are-and-how-to-stop-them/
[2]: https://www.accessagility.com/rogue-wifi-wireless-access-point-ap
[3]: https://zimperium.com/glossary/rogue-access-point/
[4]: https://jumpcloud.com/it-index/what-is-a-rogue-access-point

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


