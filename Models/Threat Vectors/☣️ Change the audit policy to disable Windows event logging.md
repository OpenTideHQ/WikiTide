

# ☣️ Change the audit policy to disable Windows event logging

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1562.002 : Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002 'Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits Windows event logs record user and system ')



---

`🔑 UUID : 36694031-a3d8-474e-b0e6-f44ba94c2a22` **|** `🏷️ Version : 3` **|** `🗓️ Creation Date : 2023-01-05` **|** `🗓️ Last Modification : 2023-01-06` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> A threat actor may change an audit policy setting with the purpose of
> disabling Event logging for specific entries. Usually the threat actor will
> disable specific audit policy entries, but other scenarios can be imagined.
> 
> For example, they can change the audit policy settings manually, with
> PowerShell or other scripts, through the registries or by using
> Command-line interface.
> 
> Examples: 
> 
> Command-prompt (cmd) interface:
> 
> auditpol /set /category:"Account Logon" /success:disable /failure:disable
> 
> Where /success or /failure are parameters used for disabling of successful
> or failed events.
> 
> auditpol /Set /Category:* /success:disable
> 
> Where the parameter /Category is used to delete only specific category, set of
> categories or all of them as shown in the example with wildcard (*) character.
> 
> auditpol /clear /y
> auditpol /remove /allusers
> 
> The both commands are used to clear the audit policy settings
> 
> PowerShell commands to modify Audit policies:
> 
> auditpol /get /category:*
> or auditpol /list/category
> PS ~> $AuditPolicyReader::GetClassicAuditPolicy()
> 
> Example for a PowerShell script that change the audit policy to audit
> successful logon events on the local computer. A threat actor can modify
> the $GPO and $SecuritySettingsPath variables to target a different GPO or
> security setting, also can modify $AuditSettingName and $AuditSettingValue
> variables to change the audit policy to a different setting or value.
> 
> Import-Module GroupPolicy
> $GPO = "LocalGPO"
> $SecuritySettingsPath = "Computer Configuration\Windows Settings\Security Settings"
> $AuditSettingName = "Audit Logon Events"
> 
> # Set the value for the security setting.
> # The values are:
> # 0 = Success and Failure
> # 1 = Success
> # 2 = Failure
> 
> $AuditSettingValue = 1
> $SecuritySettings = Get-GPRegistryValue -Name $GPO -Key $SecuritySettingsPath | Select-Object -ExpandProperty Values
> $AuditSetting = $SecuritySettings | Where-Object { $_.Name -eq $AuditSettingName }
> $AuditSetting.Value = $AuditSettingValue
> Set-GPRegistryValue -Name $GPO -Key $SecuritySettingsPath -Value $SecuritySettings
> gpupdate /force
> 
> 
> For advanced policies, threat actors can use /r to get a csv-formatted table:
> 
> auditpol /get /category:'Account Logon' /r | ConvertFrom-Csv | 
> Format-Table 'Policy Target',Subcategory,'Inclusion Setting'
> 
> Manual change: 
> 
> If the service secpol.msc is running, then a threat actor can navigate to
> Security Settings\Local Policies\Audit Policy to modify the basic policy
> settings or navigate to Security Settings\Advanced Audit Policy
> Configuration to modify advanced policy settings.
> 



## 🖥️ Terrain 

 > A threat actor has gained control over a Windows endpoint and has
> privileges to disable event logging by making changes to the Windows audit
> policy.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Aliases                                                                                                                                                                                               | Source                     | Sighting               | Reference                |
|:-------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] APT29             | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020)                                                                  | Blue Kitsune, Cozy Bear, CozyDuke, Dark Halo, IRON HEMLOCK, IRON RITUAL, Midnight Blizzard, NOBELIUM, NobleBaron, SolarStorm, The Dukes, UNC2452, UNC3524, YTTRIUM                                    | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| UNC2452                        | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | DarkHalo, StellarParticle, NOBELIUM, Solar Phoenix, Midnight Blizzard                                                                                                                                 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Mobile] Sandworm Team         | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018) | APT44, BlackEnergy (Group), ELECTRUM, FROZENBARENTS, IRIDIUM, IRON VIKING, Quedagh, Seashell Blizzard, Telebots, Voodoo Bear                                                                          | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| GreyEnergy                     | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                       | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Enterprise] Threat Group-3390 | [Threat Group-3390](https://attack.mitre.org/groups/G0027) is a Chinese threat group that has extensively used strategic Web compromises to target victims.(Citation: Dell TG-3390) The group has been active since at least 2010 and has targeted organizations in the aerospace, government, defense, technology, energy, manufacturing and gambling/betting sectors.(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Securelist LuckyMouse June 2018)(Citation: Trend Micro DRBControl February 2020)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | APT27, BRONZE UNION, Earth Smilodon, Emissary Panda, Iron Tiger, LuckyMouse, TG-3390                                                                                                                  | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| APT27                          | A China-based actor that targets foreign embassies to collect data on government, defence, and technology sectors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | GreedyTaotie, TG-3390, EMISSARY PANDA, TEMP.Hippo, Red Phoenix, Budworm, Group 35, ZipToken, Iron Tiger, BRONZE UNION, Lucky Mouse, G0027, Iron Taurus, Earth Smilodon, Circle Typhoon, Linen Typhoon | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🏃🏽 Defense Evasion`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques an attacker may specifically use for evading detection or avoiding other defenses.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖲️ Input/Output Server`](https://collaborate.mitre.org/attackics/index.php/Input/Output_Server) : The Input/Output (I/O) server provides the interface between the control system LAN applications and the field equipment monitored and controlled by the control system applications. The I/O server, sometimes referred to as a Front-End Processor (FEP) or Data Acquisition Server (DAS), converts the control system application data into packets that are transmitted over various types of communications media to the end device locations. The I/O server also converts data received from the various end devices over different communications mediums into data formatted to communicate with the control system networked applications.
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`📄 Server Logs`](http://veriscommunity.net/enums.html#section-asset) : Server - Log or event management
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Windows` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

 [`🔄 Log tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Log tampering or modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

 [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://superuser.com/questions/1516725/how-to-disable-windows-10-system-log
- [_2_] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change
- [_3_] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-change
- [_4_] https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
- [_5_] https://www.tenforums.com/performance-maintenance/170885-disable-auditing-successful-events.html
- [_6_] https://morgantechspace.com/2013/10/auditpol-command-examples-to-change.html
- [_7_] https://social.technet.microsoft.com/Forums/en-US/6268624d-b424-42b1-b5ff-b6261a18eade/how-to-permanently-disable-auditing-in-windows-10
- [_8_] https://superuser.com/questions/1059822/change-audit-policy-through-the-registry
- [_9_] https://stackoverflow.com/questions/67974297/using-powershell-to-get-the-audit-policy-security-setting-value

[1]: https://superuser.com/questions/1516725/how-to-disable-windows-10-system-log
[2]: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change
[3]: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-change
[4]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
[5]: https://www.tenforums.com/performance-maintenance/170885-disable-auditing-successful-events.html
[6]: https://morgantechspace.com/2013/10/auditpol-command-examples-to-change.html
[7]: https://social.technet.microsoft.com/Forums/en-US/6268624d-b424-42b1-b5ff-b6261a18eade/how-to-permanently-disable-auditing-in-windows-10
[8]: https://superuser.com/questions/1059822/change-audit-policy-through-the-registry
[9]: https://stackoverflow.com/questions/67974297/using-powershell-to-get-the-audit-policy-security-setting-value

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


