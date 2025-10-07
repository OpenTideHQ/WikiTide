

# ☣️ Abuse of environment variable to hijack library functions

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1574.006 : Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006 'Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries During the ex')



---

`🔑 UUID : 4d0bd987-1430-4433-9b58-a71ba8798435` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-01-10` **|** `🗓️ Last Modification : 2025-01-10` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> This threat vector focuses on the malicious use of the `LD_PRELOAD` environment 
> variable on Linux systems to hook or hijack library function calls. Attackers, 
> Red Teams, and advanced persistent threats leverage this trick to intercept and 
> modify the behavior of dynamically linked libraries before the legitimate 
> functions are called. By loading a rogue or malicious library via `LD_PRELOAD`, 
> adversaries can achieve elevated privileges, persist on the target, and run 
> arbitrary code under the guise of otherwise legitimate processes.    
> 
> Scenario example: 
> - An attacker already possessing local or remote administrative access to a Linux 
> host can set or modify the `LD_PRELOAD` environment variable in order to inject 
> custom libraries during program execution.   
> 
> - When an application starts, the system dynamic linker reads the `LD_PRELOAD` variable 
> and forces the loading of the malicious library.  
> 
> - The malicious library intercepts and potentially manipulates function calls—such as 
> file I/O or network operations—allowing attackers to subvert security controls or 
> execute code of their choice.
> 
> ```bash
> LD_PRELOAD=/tmp/malicious.so /usr/bin/anyApp
> ```
> 
> This indicates that a potentially unauthorized library (`/tmp/malicious.so`) is being 
> force-loaded into `anyApp`.  
> 



## 🖥️ Terrain 

 > Threat actor must have sufficient privileges to modify environment variables or 
> system configurations and deploy malicious libraries in the filesystem in order 
> to hijack library calls via LD_PRELOAD.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Aliases                                                                                                                                                                                    | Source                     | Sighting               | Reference                |
|:---------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] TeamTNT | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021)                                                                                                                                                                                                                                                   |                                                                                                                                                                                            | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| TeamTNT              | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim.They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware.TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany.                                                | Adept Libra                                                                                                                                                                                | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Enterprise] APT37   | [APT37](https://attack.mitre.org/groups/G0067) is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait, and other parts of the Middle East. [APT37](https://attack.mitre.org/groups/G0067) has also been linked to the following campaigns between 2016-2018: Operation Daybreak, Operation Erebus, Golden Time, Evil New Year, Are you Happy?, FreeMilk, North Korean Human Rights, and Evil New Year 2018.(Citation: FireEye APT37 Feb 2018)(Citation: Securelist ScarCruft Jun 2016)(Citation: Talos Group123)North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups. | Group123, InkySquid, Reaper, Ricochet Chollima, ScarCruft, TEMP.Reaper                                                                                                                     | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| APT37                | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | APT 37, Group 123, Group123, InkySquid, Operation Daybreak, Operation Erebus, Reaper Group, Reaper, Red Eyes, Ricochet Chollima, ScarCruft, Venus 121, ATK4, G0067, Moldy Pisces, APT-C-28 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🥸 Privilege Escalation`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : The result of techniques that provide an attacker with higher permissions on a system or network.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`📄 Server Logs`](http://veriscommunity.net/enums.html#section-asset) : Server - Log or event management

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Linux` : Placeholder
 - ` Docker Engine` : Placeholder
 - ` Kubernetes` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`👽 Alter behavior`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Influence or alter human behavior

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`💸 Monetary Loss`](http://veriscommunity.net/enums.html#section-impact) : The vector will directly conduct to loss of value directly impacting the bottom line.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://research.splunk.com/endpoint/35c50572-a70b-452f-afa9-bebdf3c3ce36/
- [_2_] https://www.getambassador.io/blog/code-injection-on-linux-and-macos
- [_3_] https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/

[1]: https://research.splunk.com/endpoint/35c50572-a70b-452f-afa9-bebdf3c3ce36/
[2]: https://www.getambassador.io/blog/code-injection-on-linux-and-macos
[3]: https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


