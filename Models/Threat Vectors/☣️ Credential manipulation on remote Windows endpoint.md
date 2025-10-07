

# ☣️ Credential manipulation on remote Windows endpoint

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1098.001 : Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001 'Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the envi'), [T1003 : OS Credential Dumping](https://attack.mitre.org/techniques/T1003 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password C')



---

`🔑 UUID : cfc6369a-e3df-4827-bb0d-969342f1558c` **|** `🏷️ Version : 6` **|** `🗓️ Creation Date : 2023-01-27` **|** `🗓️ Last Modification : 2023-02-07` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Threat actors can perform credential manipulation on a remote Windows
> endpoint with a variety of tools like: Mimikatz, WMIExec, WinRM-based,
> PsExec, SMBExec or PowerShell or others to extract credentials from
> a credential storage point on the endpoint, as example from the endpoint's
> memory. This can be done by an attacker who already has gained access to
> and control of one endpoint.
> 
> Requirements:
> 
> - permissions to access the remote machine
> - permission/ability to run credential dumping tools
> - or an ability to start a service remotely
> 
> Impacket PsExec example with username and password:
> 
> python3 psexec.py <domain>/<user>:<pass>@<target_host>
> 
> or an option with NTLM hashes
> 
> python3 psexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>
> 
> Example for Impacket SMBExec with plaintext credentials and NTLM hashes:
> 
> python3 smbexec.py "<domain>/<user>:<password>"@<target_host>
> 
> python3 smbexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>
> 
> Impacket suite contains a python script and can read the content of the
> registry keys and decrypt the LSA Secrets passwords.
> 
> Example:
> 
> impacket-secretdump -sam /root/Desktop/sam.save -security /root/Desktop/security.save -system /root/Desktop/system.save LOCAL
> 



## 🖥️ Terrain 

 > Requires an already compromised Windows endpoint.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Aliases                                                                                                                         | Source                     | Sighting               | Reference                |
|:---------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Mobile] Sandworm Team     | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018)                                                                                                                                                                                                                                                                                    | APT44, BlackEnergy (Group), ELECTRUM, FROZENBARENTS, IRIDIUM, IRON VIKING, Quedagh, Seashell Blizzard, Telebots, Voodoo Bear    | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| GreyEnergy                 | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |                                                                                                                                 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Enterprise] MuddyWater    | [MuddyWater](https://attack.mitre.org/groups/G0069) is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).(Citation: CYBERCOM Iranian Intel Cyber January 2022) Since at least 2017, [MuddyWater](https://attack.mitre.org/groups/G0069) has targeted a range of government and private organizations across sectors, including telecommunications, local government, defense, and oil and natural gas organizations, in the Middle East, Asia, Africa, Europe, and North America.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Earth Vetala, MERCURY, Mango Sandstorm, Seedworm, Static Kitten, TA450, TEMP.Zagros                                             | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| MuddyWater                 | The MuddyWater attacks are primarily against Middle Eastern nations. However, we have also observed attacks against surrounding nations and beyond, including targets in India and the USA. MuddyWater attacks are characterized by the use of a slowly evolving PowerShell-based first stage backdoor we call “POWERSTATS”. Despite broad scrutiny and reports on MuddyWater attacks, the activity continues with only incremental changes to the tools and techniques.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | TEMP.Zagros, Static Kitten, Seedworm, MERCURY, COBALT ULSTER, G0069, ATK51, Boggy Serpens, Mango Sandstorm, TA450, Earth Vetala | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Enterprise] Mustang Panda | [Mustang Panda](https://attack.mitre.org/groups/G0129) is a China-based cyber espionage threat actor that was first observed in 2017 but may have been conducting operations since at least 2014. [Mustang Panda](https://attack.mitre.org/groups/G0129) has targeted government entities, nonprofits, religious, and other non-governmental organizations in the U.S., Europe, Mongolia, Myanmar, Pakistan, and Vietnam, among others.(Citation: Crowdstrike MUSTANG PANDA June 2018)(Citation: Anomali MUSTANG PANDA October 2019)(Citation: Secureworks BRONZE PRESIDENT December 2019)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | BRONZE PRESIDENT, RedDelta, TA416                                                                                               | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| RedDelta                   | Likely Chinese state-sponsored threat activity group RedDelta targeting organizations within Europe and Southeast Asia using a customized variant of the PlugX backdoor. Since at least 2019, RedDelta has been consistently active within Southeast Asia, particularly in Myanmar and Vietnam, but has also routinely adapted its targeting in response to global geopolitical events. This is historically evident through the group’s targeting of the Vatican and other Catholic organizations in the lead-up to 2021 talks between Chinese Communist Party (CCP) and Vatican officials, as well as throughout 2022 through the group’s shift towards increased targeting of European government and diplomatic entities following Russia’s invasion of Ukraine.During the 3-month period from September through November 2022, RedDelta has regularly used an infection chain employing malicious shortcut (LNK) files, which trigger a dynamic-link library (DLL) search-order-hijacking execution chain to load consistently updated PlugX versions. Throughout this period, the group repeatedly employed decoy documents specific to government and migration policy within Europe. Of note, we identified a European government department focused on trade communicating with RedDelta command-and-control (C2) infrastructure in early August 2022. This activity commenced on the same day that a RedDelta PlugX sample using this C2 infrastructure and featuring an EU trade-themed decoy document surfaced on public malware repositories. We also identified additional probable victim entities within Myanmar and Vietnam regularly communicating with RedDelta C2 infrastructure.RedDelta closely overlaps with public industry reporting under the aliases BRONZE PRESIDENT, Mustang Panda, TA416, Red Lich, and HoneyMyte. |                                                                                                                                 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`⚡ Execution`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques that result in execution of attacker-controlled code on a local or remote system.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`📧 Email Platform`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` Windows` : Placeholder
 - ` Active Directory` : Placeholder
 - ` PowerShell` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

 [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

 [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://pypi.org/project/pypsexec/
- [_2_] https://stackoverflow.com/questions/24963625/psexec-run-python-script-passed-from-host
- [_3_] https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to/
- [_4_] https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/
- [_5_] https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-victims
- [_6_] https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
- [_7_] https://www.sentinelone.com/cybersecurity-101/mimikatz/
- [_8_] https://www.cisa.gov/uscert/ncas/alerts/aa22-011a
- [_9_] https://resources.infosecinstitute.com/topic/apt-sandworm-notpetya-technical-overview/
- [_10_] https://www.avertium.com/resources/threat-reports/in-depth-iranian-apt-muddywater

[1]: https://pypi.org/project/pypsexec/
[2]: https://stackoverflow.com/questions/24963625/psexec-run-python-script-passed-from-host
[3]: https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to/
[4]: https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/
[5]: https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-victims
[6]: https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
[7]: https://www.sentinelone.com/cybersecurity-101/mimikatz/
[8]: https://www.cisa.gov/uscert/ncas/alerts/aa22-011a
[9]: https://resources.infosecinstitute.com/topic/apt-sandworm-notpetya-technical-overview/
[10]: https://www.avertium.com/resources/threat-reports/in-depth-iranian-apt-muddywater

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


