

# ☣️ Web Shell Attacks

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1505.003 : Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003 'Adversaries may backdoor web servers with web shells to establish persistent access to systems A Web shell is a Web script that is placed on an openly')



---

`🔑 UUID : 4d6104e3-10d4-4a12-b081-d937df848891` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-07-08` **|** `🗓️ Last Modification : 2025-10-01` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.



## 🖥️ Terrain 

 > Adversary access to a compromise Web server with vulnerability or account to upload and serve the Web shell file.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Aliases                                                                                                                                                            | Source                     | Sighting               | Reference                |
|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] APT29 | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) | Blue Kitsune, Cozy Bear, CozyDuke, Dark Halo, IRON HEMLOCK, IRON RITUAL, Midnight Blizzard, NOBELIUM, NobleBaron, SolarStorm, The Dukes, UNC2452, UNC3524, YTTRIUM | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| UNC2452            | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | DarkHalo, StellarParticle, NOBELIUM, Solar Phoenix, Midnight Blizzard                                                                                              | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





 --- 

### ⛓️ Threat Chaining

```mermaid

flowchart LR

4b1c47ee-f45a-4b89-98e7-e943bcd5dd19[Command injection on web components of Ivanti Connect Secure appliances]
4d6104e3-10d4-4a12-b081-d937df848891[Web Shell Attacks]
810057c6-cb84-41e4-add4-ae56b52c8ab7[authentication bypass on Ivanti Connect Secure appliances]

subgraph Exploitation
4b1c47ee-f45a-4b89-98e7-e943bcd5dd19
810057c6-cb84-41e4-add4-ae56b52c8ab7
end
subgraph Persistence
4d6104e3-10d4-4a12-b081-d937df848891
end

CVE-2024-21887>CVE-2024-21887]
CVE-2024-21888>CVE-2024-21888]
CVE-2024-21893>CVE-2024-21893]
CVE-2023-46805>CVE-2023-46805]
CVE-2024-22024>CVE-2024-22024]
Gelsemium{{Gelsemium}}
APT29{{APT29}}
UNC2452{{UNC2452}}

4b1c47ee-f45a-4b89-98e7-e943bcd5dd19 -.->|exploits| CVE-2024-21887
4b1c47ee-f45a-4b89-98e7-e943bcd5dd19 -.->|exploits| CVE-2024-21888
4b1c47ee-f45a-4b89-98e7-e943bcd5dd19 -.->|exploits| CVE-2024-21893
810057c6-cb84-41e4-add4-ae56b52c8ab7 -.->|exploits| CVE-2023-46805
810057c6-cb84-41e4-add4-ae56b52c8ab7 -.->|exploits| CVE-2024-21888
810057c6-cb84-41e4-add4-ae56b52c8ab7 -.->|exploits| CVE-2024-21893
810057c6-cb84-41e4-add4-ae56b52c8ab7 -.->|exploits| CVE-2024-22024
Gelsemium -.-> |performs| 4b1c47ee-f45a-4b89-98e7-e943bcd5dd19
APT29 -.-> |performs| 4d6104e3-10d4-4a12-b081-d937df848891
UNC2452 -.-> |performs| 4d6104e3-10d4-4a12-b081-d937df848891
Gelsemium -.-> |performs| 810057c6-cb84-41e4-add4-ae56b52c8ab7

4b1c47ee-f45a-4b89-98e7-e943bcd5dd19 -->|enabling| 4d6104e3-10d4-4a12-b081-d937df848891
4b1c47ee-f45a-4b89-98e7-e943bcd5dd19 <-->|synergize| 810057c6-cb84-41e4-add4-ae56b52c8ab7

```


<details>
<summary>Expand chaining data</summary>

| ☣️ Vector                                                                                                                                                                                                                                                                                                                                                    | ⛓️ Link              | 🎯 Target                                                                                                                                                                                                                                                                                                                   | ⛰️ Terrain                                                                                                        | 🗡️ ATT&CK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Command injection on web components of Ivanti Connect Secure appliances](../Threat%20Vectors/☣️%20Command%20injection%20on%20web%20components%20of%20Ivanti%20Connect%20Secure%20appliances.md 'Attackers may manage to inject commands to an Ivanti Connect Secure appliance that provide remote VPN access to corporate infrastructures either with ...') | `support::enabling`  | [Web Shell Attacks](../Threat%20Vectors/☣️%20Web%20Shell%20Attacks.md 'Adversaries may backdoor web servers with web shells to establish persistent access to systems A Web shell is a Web script that is placed on an openly...')                                                                                         | Adversary access to a compromise Web server with vulnerability or account to upload and serve the Web shell file. | [T1505.003 : Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003 'Adversaries may backdoor web servers with web shells to establish persistent access to systems A Web shell is a Web script that is placed on an openly')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [Command injection on web components of Ivanti Connect Secure appliances](../Threat%20Vectors/☣️%20Command%20injection%20on%20web%20components%20of%20Ivanti%20Connect%20Secure%20appliances.md 'Attackers may manage to inject commands to an Ivanti Connect Secure appliance that provide remote VPN access to corporate infrastructures either with ...') | `support::synergize` | [authentication bypass on Ivanti Connect Secure appliances](../Threat%20Vectors/☣️%20authentication%20bypass%20on%20Ivanti%20Connect%20Secure%20appliances.md '### chained exploitation of CVE-2023-46805 or CVE-2024-21893 together with CVE-2024-21887Attackers may chain exploits on vulnerabilities CVE-2023-4680...') | Ivanti Connect Secure appliance vulnerable to authentication bypass (CVE-2023-46805)                              | [T1011 : Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011 'Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel If the command and control network is '), [T1041 : Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041 'Adversaries may steal data by exfiltrating it over an existing command and control channel Stolen data is encoded into the normal communications chann'), [T1070 : Indicator Removal](https://attack.mitre.org/techniques/T1070 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses Various artifacts may be c'), [T1190 : Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network The weakness in the system can be a s') |

</details>
&nbsp; 


---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔐 Persistence`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Any access, action or change to a system that gives an attacker persistent presence on the system.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Linux` : Placeholder
 - ` Windows` : Placeholder
 - ` macOS` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`💅 Modify privileges`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify privileges or permissions

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.imperva.com/learn/application-security/web-shell/
- [_2_] https://capec.mitre.org/data/definitions/650.html
- [_3_] https://attack.mitre.org/techniques/T1505/003/

[1]: https://www.imperva.com/learn/application-security/web-shell/
[2]: https://capec.mitre.org/data/definitions/650.html
[3]: https://attack.mitre.org/techniques/T1505/003/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


