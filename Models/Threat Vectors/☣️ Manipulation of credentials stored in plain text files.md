

# ☣️ Manipulation of credentials stored in plain text files

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1552 : Unsecured Credentials](https://attack.mitre.org/techniques/T1552 'Adversaries may search compromised systems to find and obtain insecurely stored credentials These credentials can be stored andor misplaced in many lo'), [T1565 : Data Manipulation](https://attack.mitre.org/techniques/T1565 'Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the dat'), [T1003 : OS Credential Dumping](https://attack.mitre.org/techniques/T1003 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password C'), [T1555.003 : Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003 'Adversaries may acquire credentials from web browsers by reading files specific to the target browserCitation Talos Olympic Destroyer 2018 Web browser'), [T1110.002 : Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002 'Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password'), [T1003.007 : OS Credential Dumping: Proc Filesystem](https://attack.mitre.org/techniques/T1003/007 'Adversaries may gather credentials from the proc filesystem or proc The proc filesystem is a pseudo-filesystem used as an interface to kernel data str')



---

`🔑 UUID : 82dce94c-7b18-4cb9-bae0-56716b580418` **|** `🏷️ Version : 3` **|** `🗓️ Creation Date : 2023-01-30` **|** `🗓️ Last Modification : 2023-02-03` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Threat actors are searching for credentials stored in plain text, usually in
> an application's properties, configuration files, system memory or other
> places in the system. Storing a plain text password could lead to data
> leakage because, for example when the passwords are stored in clear text
> in a configuration file everyone who has read access to the file can see
> and steal the passwords. In most cases, even storage of a plaintext
> password in a memory is considered as a security risk if the password
> is not cleared immediately after it is used. Good password management
> policies require that a password shouldn't be stored in a plaintext.
> 
> In some cases the user's passwords are stored in plain text when a program
> application or system file crates and saves them automatically in a file
> without encryption. In other cases the credentials can be stored in clear 
> text by user's mistake. Threat actors are using different methods like:
> password cracking, dictionary attack, social engineering and phishing
> attacks, man in the middle attack, malware injections and others to steal
> and manipulate credentials stored in a plain text.
> 
> One example of manipulation of credentials stored in plain text files is by
> using a technique called "password cracking." This involves using a computer
> program to repeatedly guess a password or its hash until the correct one is
> found. If the plain text file containing the credentials is not properly
> secured, an attacker could gain access to sensitive information such as
> username and password combinations. Threat actors are using variety of
> different tools to crack user's credentials, for example: John the Ripper,
> Hashcat, Aircrack-ng, Cain and Abel, Mimikatz, custom python scripts and
> others. 
> 
> Example for a code that reads a password from a properties file and uses
> the password to connect to a database:
> 
> Properties prop = new Properties();
> prop.load(new FileInputStream("config.properties"));
> String password = prop.getProperty("password");
> 
> DriverManager.getConnection(url, usr, password);
> 
> Example for a python script scanning for files stored in a clear text:
> 
> # put your path here 
> # Network SMB path you want to search 
> root_dir = ("xxxxxx", "etc.")
> # location where you want to put the result 
> stored_dir = 'xxxxxxxxx'
> # exception you want to filter
> exception_path = ["snapshot"]
> 



## 🖥️ Terrain 

 > A threat actor is using an already compromised Windows endpoint.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Aliases                                                                                                                                                                                    | Source                     | Sighting               | Reference                |
|:--------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] APT29  | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) | Blue Kitsune, Cozy Bear, CozyDuke, Dark Halo, IRON HEMLOCK, IRON RITUAL, Midnight Blizzard, NOBELIUM, NobleBaron, SolarStorm, The Dukes, UNC2452, UNC3524, YTTRIUM                         | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| UNC2452             | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | DarkHalo, StellarParticle, NOBELIUM, Solar Phoenix, Midnight Blizzard                                                                                                                      | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Enterprise] APT37  | [APT37](https://attack.mitre.org/groups/G0067) is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait, and other parts of the Middle East. [APT37](https://attack.mitre.org/groups/G0067) has also been linked to the following campaigns between 2016-2018: Operation Daybreak, Operation Erebus, Golden Time, Evil New Year, Are you Happy?, FreeMilk, North Korean Human Rights, and Evil New Year 2018.(Citation: FireEye APT37 Feb 2018)(Citation: Securelist ScarCruft Jun 2016)(Citation: Talos Group123)North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Group123, InkySquid, Reaper, Ricochet Chollima, ScarCruft, TEMP.Reaper                                                                                                                     | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| APT37               | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | APT 37, Group 123, Group123, InkySquid, Operation Daybreak, Operation Erebus, Reaper Group, Reaper, Red Eyes, Ricochet Chollima, ScarCruft, Venus 121, ATK4, G0067, Moldy Pisces, APT-C-28 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [ICS] FIN6          | [FIN6](https://attack.mitre.org/groups/G0037) is a cyber crime group that has stolen payment card data and sold it for profit on underground marketplaces. This group has aggressively targeted and compromised point of sale (PoS) systems in the hospitality and retail sectors.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Camouflage Tempest, ITG08, Magecart Group 6, Skeleton Spider, TAAL                                                                                                                         | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| FIN6                | FIN is a group targeting financial assets including assets able to do financial transaction including PoS.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | SKELETON SPIDER, ITG08, MageCart Group 6, White Giant, GOLD FRANKLIN, ATK88, G0037, Camouflage Tempest, TA4557, Storm-0538                                                                 | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [Mobile] LAPSUS$    | [LAPSUS$](https://attack.mitre.org/groups/G1004) is cyber criminal threat group that has been active since at least mid-2021. [LAPSUS$](https://attack.mitre.org/groups/G1004) specializes in large-scale social engineering and extortion operations, including destructive attacks without the use of ransomware. The group has targeted organizations globally, including in the government, manufacturing, higher education, energy, healthcare, technology, telecommunications, and media sectors.(Citation: BBC LAPSUS Apr 2022)(Citation: MSTIC DEV-0537 Mar 2022)(Citation: UNIT 42 LAPSUS Mar 2022)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | DEV-0537, Strawberry Tempest                                                                                                                                                               | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| LAPSUS              | An actor group conducting large-scale social engineering and extortion campaign against multiple organizations with some seeing evidence of destructive elements.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | LAPSUS$, DEV-0537, SLIPPY SPIDER, Strawberry Tempest                                                                                                                                       | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [ICS] FIN7          | [FIN7](https://attack.mitre.org/groups/G0046) is a financially-motivated threat group that has been active since 2013. [FIN7](https://attack.mitre.org/groups/G0046) has primarily targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, and utilities industries in the U.S. A portion of [FIN7](https://attack.mitre.org/groups/G0046) was run out of a front company called Combi Security and often used point-of-sale malware for targeting efforts. Since 2020, [FIN7](https://attack.mitre.org/groups/G0046) shifted operations to a big game hunting (BGH) approach including use of [REvil](https://attack.mitre.org/software/S0496) ransomware and their own Ransomware as a Service (RaaS), Darkside. FIN7 may be linked to the [Carbanak](https://attack.mitre.org/groups/G0008) Group, but there appears to be several groups using [Carbanak](https://attack.mitre.org/software/S0030) malware and are therefore tracked separately.(Citation: FireEye FIN7 March 2017)(Citation: FireEye FIN7 April 2017)(Citation: FireEye CARBANAK June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)                                                                                                                                                                                            | Carbon Spider, ELBRUS, GOLD NIAGARA, ITG14, Sangria Tempest                                                                                                                                | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| FIN7                | Groups targeting financial organizations or people with significant financial assets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | CARBON SPIDER, GOLD NIAGARA, Calcium, ATK32, G0046, G0008, Coreid, Carbanak, Sangria Tempest, ELBRUS, Carbon Spider, JokerStash                                                            | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |
| [ICS] Wizard Spider | [Wizard Spider](https://attack.mitre.org/groups/G0102) is a Russia-based financially motivated threat group originally known for the creation and deployment of [TrickBot](https://attack.mitre.org/software/S0266) since at least 2016. [Wizard Spider](https://attack.mitre.org/groups/G0102) possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.(Citation: CrowdStrike Ryuk January 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: CrowdStrike Wizard Spider October 2020)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | DEV-0193, FIN12, GOLD BLACKBURN, Grim Spider, ITG23, Periwinkle Tempest, TEMP.MixMaster, UNC1878                                                                                           | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| UNC1878             | UNC1878 is a financially motivated threat actor that monetizes network access via the deployment of RYUK ransomware. Earlier this year, Mandiant published a blog on a fast-moving adversary deploying RYUK ransomware, UNC1878. Shortly after its release, there was a significant decrease in observed UNC1878 intrusions and RYUK activity overall almost completely vanishing over the summer. But beginning in early fall, Mandiant has seen a resurgence of RYUK along with TTP overlaps indicating that UNC1878 has returned from the grave and resumed their operations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |                                                                                                                                                                                            | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔑 Credential Access`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques resulting in the access of, or control over, system, service or domain credentials.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator
 - [`👤 Developer`](http://veriscommunity.net/enums.html#section-asset) : People - Developer
 - [`🗄️ Production Database`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

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

- [_1_] https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage
- [_2_] https://www.digitalcitizen.life/which-windows-passwords-credentials-can-be-easily-cracked/
- [_3_] https://www.passcamp.com/blog/dangers-of-storing-and-sharing-passwords-in-plaintext/
- [_4_] https://dingtoffee.medium.com/clear-text-password-scanner-58fef77e4b2d
- [_5_] https://cwe.mitre.org/data/definitions/256.html
- [_6_] https://cwe.mitre.org/data/definitions/312.html
- [_7_] https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/#h2_4
- [_8_] https://thehackernews.com/2022/11/apt29-exploited-windows-feature-to.html
- [_9_] https://malpedia.caad.fkie.fraunhofer.de/actor/apt37
- [_10_] https://know.netenrich.com/blog/fin6-know-your-threat-actor/
- [_11_] https://techcrunch.com/2022/03/23/microsoft-lapsus-hack-source-code/?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuYmluZy5jb20v&guce_referrer_sig=AQAAACu6oXda6fU_vTO_ITnANFi1ZPISubNID3kQVVIIRBVs66RYTxjTth2PCAn5DQkoUmnlR2cSzjKPPbVrUcJN1BWJpXhKL_I0Go8-xQeeROvzIhzNuEdbll2m7OY9PHeCnsjkIZJkUOrceGKkt6IAzdTE4MNMWs83kzZwWQa2UcdD
- [_12_] https://www.fbi.gov/contact-us/field-offices/seattle/news/stories/how-cyber-crime-group-fin7-attacked-and-stole-data-from-hundreds-of-us-companies

[1]: https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage
[2]: https://www.digitalcitizen.life/which-windows-passwords-credentials-can-be-easily-cracked/
[3]: https://www.passcamp.com/blog/dangers-of-storing-and-sharing-passwords-in-plaintext/
[4]: https://dingtoffee.medium.com/clear-text-password-scanner-58fef77e4b2d
[5]: https://cwe.mitre.org/data/definitions/256.html
[6]: https://cwe.mitre.org/data/definitions/312.html
[7]: https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/#h2_4
[8]: https://thehackernews.com/2022/11/apt29-exploited-windows-feature-to.html
[9]: https://malpedia.caad.fkie.fraunhofer.de/actor/apt37
[10]: https://know.netenrich.com/blog/fin6-know-your-threat-actor/
[11]: https://techcrunch.com/2022/03/23/microsoft-lapsus-hack-source-code/?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuYmluZy5jb20v&guce_referrer_sig=AQAAACu6oXda6fU_vTO_ITnANFi1ZPISubNID3kQVVIIRBVs66RYTxjTth2PCAn5DQkoUmnlR2cSzjKPPbVrUcJN1BWJpXhKL_I0Go8-xQeeROvzIhzNuEdbll2m7OY9PHeCnsjkIZJkUOrceGKkt6IAzdTE4MNMWs83kzZwWQa2UcdD
[12]: https://www.fbi.gov/contact-us/field-offices/seattle/news/stories/how-cyber-crime-group-fin7-attacked-and-stole-data-from-hundreds-of-us-companies

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


