

# ☣️ Supply chain compromise via software update mechanism

🔥 **Criticality:Emergency** ☢️ : An Emergency priority incident poses an imminent threat to the provision of wide-scale critical infrastructure services, national government stability, or human lives. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002 'Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise Supply chain comprom'), [T1195 : Supply Chain Compromise](https://attack.mitre.org/techniques/T1195 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromiseSu'), [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses '), [T1078 : Valid Accounts](https://attack.mitre.org/techniques/T1078 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense '), [T1218.011 : System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011 'Adversaries may abuse rundll32exe to proxy execution of malicious code Using rundll32exe, vice executing directly ie Shared Moduleshttpsattackmitreorg'), [T1027 : Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents '), [T1140 : Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140 'Adversaries may use Obfuscated Files or InformationhttpsattackmitreorgtechniquesT1027 to hide artifacts of an intrusion from analysis They may require'), [T1071 : Application Layer Protocol](https://attack.mitre.org/techniques/T1071 'Adversaries may communicate using OSI application layer protocols to avoid detectionnetwork filtering by blending in with existing traffic Commands to'), [T1071.001 : Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detectionnetwork filtering by blending in with exis'), [T1095 : Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095 'Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network The li'), [T1571 : Non-Standard Port](https://attack.mitre.org/techniques/T1571 'Adversaries may communicate using a protocol and port pairing that are typically not associated For example, HTTPS over port 8088Citation Symantec Elf'), [T1573 : Encrypted Channel](https://attack.mitre.org/techniques/T1573 'Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a co'), [T1070 : Indicator Removal](https://attack.mitre.org/techniques/T1070 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses Various artifacts may be c'), [T1070.004 : Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004 'Adversaries may delete files left behind by the actions of their intrusion activity Malware, tools, or other non-native files dropped or created on a '), [T1070.006 : Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006 'Adversaries may modify file time attributes to hide new files or changes to existing files Timestomping is a technique that modifies the timestamps of'), [T1562.001 : Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001 'Adversaries may modify andor disable security tools to avoid possible detection of their malwaretools and activities This may take many forms, such as'), [T1562 : Impair Defenses](https://attack.mitre.org/techniques/T1562 'Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms This not only involves impair'), [T1036.005 : Masquerading: Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005 'Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when namingplacing them This is done '), [T1036 : Masquerading](https://attack.mitre.org/techniques/T1036 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users andor security tools Masquerading ')



---

`🔑 UUID : 7290ceff-561d-49e2-b5a4-c4cfd29c09f7` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-10-15` **|** `🗓️ Last Modification : 2025-10-15` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> The SolarWinds supply chain attack, also known as SUNBURST or Solorigate, represents one of the 
> most sophisticated cyber espionage campaigns in history. Between March and June 2020, threat actors 
> compromised the software build and distribution system of SolarWinds, a major IT management software 
> provider. The attackers injected malicious code into legitimate software updates of the SolarWinds 
> Orion Platform, affecting approximately 18,000 customers worldwide.
> 
> ## Attack Methodology
> 
> The attack unfolded in multiple sophisticated stages:
> 
> ### Initial Compromise
> Threat actors gained access to SolarWinds' software development environment, potentially through
> compromised credentials or exploitation of vulnerabilities. This initial access provided the attackers
> with the ability to modify the Orion Platform source code during the build process.
> 
> ### Malicious Code Injection
> The attackers injected a backdoor (dubbed SUNBURST/Solorigate) into the SolarWinds.Orion.Core.BusinessLayer.dll
> dynamic link library. The malicious code was designed to:
> - Remain dormant for approximately 12-14 days after installation
> - Masquerade as legitimate Orion Improvement Program (OIP) functionality
> - Use domain generation algorithms (DGA) to resolve command and control infrastructure
> - Employ multiple evasion techniques to avoid detection
> 
> ### Distribution via Legitimate Updates
> The trojanized updates were digitally signed with SolarWinds' legitimate code-signing certificate,
> lending credibility to the malicious packages. Organizations that automatically applied updates or
> manually installed updates between versions 2019.4 through 2020.2.1 HF1 unknowingly deployed the backdoor.
> 
> ### Command and Control
> SUNBURST used sophisticated C2 mechanisms:
> - DNS requests to avsvmcloud[.]com to resolve actual C2 servers
> - HTTP/HTTPS communications disguised as Orion Improvement Program traffic
> - Multiple C2 domains using cloud and content delivery networks
> - Victim-specific C2 infrastructure allocation
> 
> ### Post-Exploitation Activities
> After establishing persistent access, attackers:
> - Conducted extensive reconnaissance of victim networks
> - Moved laterally to cloud environments (Azure, Microsoft 365)
> - Stole authentication credentials and certificates
> - Accessed sensitive email communications
> - Deployed additional backdoors and tools (TEARDROP, RAINDROP, etc.)
> - Maintained long-term persistent access
> 
> ## Impact and Scope
> 
> The campaign affected numerous high-value targets including:
> - U.S. government agencies (Treasury, State, Commerce, Homeland Security, Energy, NIH)
> - Critical infrastructure organizations
> - Technology companies (Microsoft, Cisco, Intel, VMware, Palo Alto Networks)
> - Telecommunications providers
> - Think tanks and consulting firms
> - Over 100 private sector companies
> 
> ## Detection Challenges
> 
> The attack was particularly difficult to detect due to:
> - Use of legitimate, signed software updates
> - Sophisticated operational security practices
> - Low-and-slow approach to avoid anomaly detection
> - Use of victim infrastructure for C2 communications
> - Minimal forensic artifacts
> - Encrypted communications
> - Integration with legitimate network management tools
> 
> ## Defense Recommendations
> 
> Organizations should implement multiple layers of defense:
> - Enhanced supply chain security assessment
> - Software composition analysis
> - Code signing verification and monitoring
> - Network traffic analysis for anomalous patterns
> - Enhanced endpoint detection and response (EDR)
> - Privileged access management
> - Zero-trust architecture implementation
> - Regular security audits of third-party software
> - Incident response planning for supply chain compromises
> 
> This threat vector demonstrates the catastrophic potential of supply chain compromises and the
> need for comprehensive security measures that extend beyond traditional perimeter defenses to
> encompass the entire software development and distribution lifecycle.
> 



## 🖥️ Terrain 

 > Organizations using the compromised software (SolarWinds Orion Platform versions 2019.4 through 2020.2.1 HF1)
> that installed trojanized updates between March and June 2020. The attack vector requires:
> - Legitimate software update mechanism in place
> - Trust relationship between software vendor and customer
> - Network connectivity to software vendor update servers
> - Administrative privileges for software installation/update
> - Insufficient supply chain security controls
> - Limited visibility into software build and update processes
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Aliases                                                                                                                                                            | Source                 | Sighting               | Reference                |
|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------|:-----------------------|:-------------------------|
| [Enterprise] APT29 | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) | Blue Kitsune, Cozy Bear, CozyDuke, Dark Halo, IRON HEMLOCK, IRON RITUAL, Midnight Blizzard, NOBELIUM, NobleBaron, SolarStorm, The Dukes, UNC2452, UNC3524, YTTRIUM | 🗡️ MITRE ATT&CK Groups | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `🕸️ SaaS` : Subscription based access to software.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`💿 Production Software`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🛠️ Development Pipelines`](http://veriscommunity.net/enums.html#section-asset) : Development pipelines outline the stages and workflows involved in the software development process, from initial development to testing, integration, and deployment.
 - [`🛠️ Software Development Tools`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`👤 Identity Services`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`☁️ Cloud Portal`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🧩 API Endpoints`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Azure` : Placeholder
 - ` Azure AD` : Placeholder
 - ` Office 365` : Placeholder
 - ` AWS` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`☢️ National cyber emergency`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which causes sustained disruption of (inter)national essential services or affects (inter)national national security, leading to severe economic or social consequences or to loss of life.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👻 Spoofing`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at accessing and use of another user’s credentials, such as username and password.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🎖️ National Security`](http://veriscommunity.net/enums.html#section-impact) : The vector execution will expose or destroy such sufficient critical information infrastructure that the country will have to intervene due to loss to key national  or international functions.
 - [`☄️ Catastrophic Loss`](http://veriscommunity.net/enums.html#section-impact) : The organization will lose a major part of its capacity to fulfill its strategic objective, and may not be able to recover fully or at all.
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`🌍 Reputational Damages`](http://veriscommunity.net/enums.html#section-impact) : Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`😰 Very Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Highly probable - 80-95%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- [_2_] https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
- [_3_] https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- [_4_] https://attack.mitre.org/campaigns/C0024/
- [_5_] https://www.ncsc.gov.uk/news/solarwinds-advisory

[1]: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
[2]: https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
[3]: https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
[4]: https://attack.mitre.org/campaigns/C0024/
[5]: https://www.ncsc.gov.uk/news/solarwinds-advisory

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


