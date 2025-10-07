

# ☣️ Abuse of 'Always-on VPN' feature on mobile device

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1133 : External Remote Services](https://attack.mitre.org/techniques/T1133 'Adversaries may leverage external-facing remote services to initially access andor persist within a network Remote services such as VPNs, Citrix, and '), [T1078 : Valid Accounts](https://attack.mitre.org/techniques/T1078 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense '), [T1195 : Supply Chain Compromise](https://attack.mitre.org/techniques/T1195 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromiseSu'), [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses ')



---

`🔑 UUID : 80329dfd-eb12-49da-9f20-565758b55eab` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-04-23` **|** `🗓️ Last Modification : 2025-04-23` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> The "Always-on VPN" feature on mobile devices is designed to ensure that all network 
> traffic is routed through a VPN tunnel, providing continuous privacy and security. 
> However, this feature can introduce specific threat vectors if abused or improperly implemented.
> 
> ### Key Threat Vectors and Risks
> 
> - **Malicious VPN Apps and Abuse of Permissions**  
>   Many VPN apps, especially on Android, have been found to abuse the permissions 
>   granted by the VPN service. Malicious or poorly designed VPN apps can:
>   - Harvest sensitive user data (such as SMS history and contact lists).
>   - Inject code or malware into network traffic.
>   - Route user traffic through untrusted third-party servers.
>   - Intercept sensitive information, including banking and social network credentials.
>   
> The "Always-on VPN" feature, if enabled with a malicious app, ensures that *all* 
> device traffic is exposed to the app, amplifying the potential for abuse and data exfiltration.
> 
> - **Traffic Leakage Despite 'Always-on VPN'**  
>   On Android, even with "Always-on VPN" and the "Block connections without VPN" 
>   (VPN Lockdown) feature enabled, some traffic can leak outside the VPN tunnel. 
>   This leakage occurs particularly when:
>   - The device connects to a new WiFi network and performs connectivity checks 
>   (such as checking for captive portals).
>   - The leaked data can include source IP addresses, DNS lookups, HTTPS, and NTP traffic.
>   
> This is a design choice in Android, and such leaks may expose user information or 
> device identifiers to local networks or attackers, undermining the privacy guarantees 
> of the VPN.
> 
> - **Split Tunneling and Unintended Bypasses**  
>   Some VPN apps or device configurations allow for split tunneling, where only certain 
>   traffic goes through the VPN. If misconfigured, sensitive data may bypass the VPN, 
>   exposing it to interception on insecure networks.
> 
> - **Device Compromise and Credential Theft**  
>   If a device with Always-on VPN is compromised (e.g., stolen or infected with malware), 
>   attackers could potentially exploit the persistent VPN connection to maintain 
>   access to internal networks or exfiltrate data. While certificate revocation and 
>   account disabling can mitigate this, there is a window of risk before such actions are taken.
>   



## 🖥️ Terrain 

 > Adversaries must obtain valid user or device credentials, or compromise authentication 
> certificates used for VPN access. This could be achieved through phishing, credential 
> theft, or exploiting weak authentication practices.
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
 - [`📱 Tablet`](http://veriscommunity.net/enums.html#section-asset) : User Device - Tablet
 - [`🛡️ VPN Client`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🪪 Personal Information`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

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

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`📉 Competitive disadvantage`](http://veriscommunity.net/enums.html#section-impact) : Loss of competitive advantage
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Maxime%20Clementz%20-%20Defeating%20VPN%20Always-On.pdf
- [_2_] https://celestix.com/docs/security-considerations-for-always-on-vpn-deployments/
- [_3_] https://www.bleepingcomputer.com/news/google/android-leaks-some-traffic-even-when-always-on-vpn-is-enabled/

[1]: https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Maxime%20Clementz%20-%20Defeating%20VPN%20Always-On.pdf
[2]: https://celestix.com/docs/security-considerations-for-always-on-vpn-deployments/
[3]: https://www.bleepingcomputer.com/news/google/android-leaks-some-traffic-even-when-always-on-vpn-is-enabled/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


