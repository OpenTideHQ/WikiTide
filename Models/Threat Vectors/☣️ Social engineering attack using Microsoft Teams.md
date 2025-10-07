

# ☣️ Social engineering attack using Microsoft Teams

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses ')



---

`🔑 UUID : 06c60af1-5fa8-493c-bf9b-6b2e215819f1` **|** `🏷️ Version : 4` **|** `🗓️ Creation Date : 2023-08-07` **|** `🗓️ Last Modification : 2025-10-01` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Adversaries are using compromised Microsoft 365 tenants to create technical
> support-themed domains and send tech support lures via Microsoft Teams, 
> attempting to trick users of the targeted organizations using social engineering.    
> 
> They aim to manipulate users into granting approval for multifactor authentication
> (MFA) prompts, ultimately aiming to steal their credentials.    
> 
> #### Attack phases    
> 
> **Preparation phase**    
> 
> Attackers compromise an Azure tenant, rename it and add a new onmicrosoft[.]com
> subdomain. It will use security-themed or product name-themed keywords to create
> a new subdomain, such as teamsprotection.onmicrosoft[.]com 
> Add a new user associated with that domain from which the attacker will send the
> outbound message to the target tenant.    
> 
> **Social engineering phase**    
> 
> Attackers send a Teams chat message to the target from the compromised external user
> masquerading as a technical support or security team; if the targeted user accepts
> the message request, attackers send a Microsoft Teams message to convince the target
> to enter a code into the Microsoft Authenticator app on his/her mobile device.
> If the targeted user enters the code into the Authenticator app, the attacker is
> granted a token to authenticate as the targeted user.    
> 
> **Post-compromise phase**    
> 
> Involves information theft from the compromised Microsoft 365 tenant, and in some 
> cases, adding a device to the organisation as a managed device through Microsoft
> Entra ID (formerly Azure Active Directory), likely an attempt to circumvent conditional
> access policies configured to restrict access to specific resources to managed devices only.    
> 
> #### Additional Tactics: Microsoft Teams Vishing    
> 
> ### Microsoft Teams Vishing    
> 
> - Attackers initiate contact via Microsoft Teams within 15-30 minutes of the email bombing.
> - They pose as IT support personnel or "Help Desk Managers".
> - Adversary-controlled Office 365 accounts are used, often with display names mimicking 
> legitimate IT staff.
> - Profile pictures and backgrounds are crafted to appear authentic.
> - Attackers exploit the victim's state of confusion and urgency caused by the email bombing.    
> 



## 🖥️ Terrain 

 > Attacker has compromised a valid Microsoft 365 tenant to host the lures, and valid
> valid credentials in targeted M365 tenant too.
> Targeted organizations must use an app like Microsoft Authenticator as second
> factor (app taking the code received after successful authentication granted by 
> the victim, the user, in previous step).
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

c4456134-df7b-4969-b5ff-a24794996890[Impersonate IT support via a spoofed phone call to deceive a victim and gain a remote access]
06c60af1-5fa8-493c-bf9b-6b2e215819f1[Social engineering attack using Microsoft Teams]
58b98d75-fc63-4662-8908-a2a7f4200902[Spearphishing with an attachment extension .rdp]
2900d389-3098-49d3-8166-5b2612d03576[Azure - Gather User Information]
0cdaee96-8595-4f3f-ba07-758b8be9d359[Social engineering without attachment or URL]
cc9003f7-a9e3-4407-a1ca-d514af469787[Lateral movement via a compromised Teams account]
b663b684-a80f-4570-89b6-2f7faa16fece[Abuse of Microsoft Office Applications]
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84[Spearphishing Attachment]
1a68b5eb-0112-424d-a21f-88dda0b6b8df[Spearphishing Link]
6a7a493a-511a-4c9d-aa9c-4427c832a322[SIM-card swapping]
4a807ac4-f764-41b1-ae6f-94239041d349[MFA Bypass Techniques]

subgraph Social Engineering
c4456134-df7b-4969-b5ff-a24794996890
0cdaee96-8595-4f3f-ba07-758b8be9d359
end
subgraph Delivery
06c60af1-5fa8-493c-bf9b-6b2e215819f1
58b98d75-fc63-4662-8908-a2a7f4200902
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
1a68b5eb-0112-424d-a21f-88dda0b6b8df
end
subgraph Reconnaissance
2900d389-3098-49d3-8166-5b2612d03576
end
subgraph Lateral Movement
cc9003f7-a9e3-4407-a1ca-d514af469787
end
subgraph Execution
b663b684-a80f-4570-89b6-2f7faa16fece
end
subgraph Credential Access
6a7a493a-511a-4c9d-aa9c-4427c832a322
4a807ac4-f764-41b1-ae6f-94239041d349
end

Windows[(Windows)]
MicrosoftTeams[(Microsoft Teams)]
iOS[(iOS)]
Android[(Android)]
AWS[(AWS)]
Azure[(Azure)]
AzureAD[(Azure AD)]
Office365[(Office 365)]
macOS[(macOS)]
MicrosoftSharePoint[(Microsoft SharePoint)]
OutlookWebAccess[(Outlook Web Access)]
Github[(Github)]
Gitlab[(Gitlab)]
EULogin[(EU Login)]
APT29{{APT29}}
UNC2452{{UNC2452}}
APT28{{APT28}}
Kimsuky{{Kimsuky}}
LazarusGroup{{Lazarus Group}}
MoonstoneSleet{{Moonstone Sleet}}
VoltTyphoon{{Volt Typhoon}}
APT38{{APT38}}
FIN7{{FIN7}}
TA505{{TA505}}
WizardSpider{{Wizard Spider}}
UNC1878{{UNC1878}}
GamaredonGroup{{Gamaredon Group}}
MustangPanda{{Mustang Panda}}
RedDelta{{RedDelta}}
RomCom{{RomCom}}
APT42{{APT42}}
LAPSUS${{LAPSUS$}}
LAPSUS{{LAPSUS}}
SandwormTeam{{Sandworm Team}}
GreyEnergy{{GreyEnergy}}
Chimera{{Chimera}}
TA406{{TA406}}

c4456134-df7b-4969-b5ff-a24794996890 -.->|targets| Windows
c4456134-df7b-4969-b5ff-a24794996890 -.->|targets| MicrosoftTeams
c4456134-df7b-4969-b5ff-a24794996890 -.->|targets| iOS
c4456134-df7b-4969-b5ff-a24794996890 -.->|targets| Android
06c60af1-5fa8-493c-bf9b-6b2e215819f1 -.->|targets| MicrosoftTeams
58b98d75-fc63-4662-8908-a2a7f4200902 -.->|targets| Windows
58b98d75-fc63-4662-8908-a2a7f4200902 -.->|targets| AWS
2900d389-3098-49d3-8166-5b2612d03576 -.->|targets| Azure
2900d389-3098-49d3-8166-5b2612d03576 -.->|targets| AzureAD
2900d389-3098-49d3-8166-5b2612d03576 -.->|targets| Office365
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| AWS
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| Azure
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| Office365
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| Windows
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| macOS
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| Android
0cdaee96-8595-4f3f-ba07-758b8be9d359 -.->|targets| iOS
cc9003f7-a9e3-4407-a1ca-d514af469787 -.->|targets| Windows
cc9003f7-a9e3-4407-a1ca-d514af469787 -.->|targets| MicrosoftTeams
b663b684-a80f-4570-89b6-2f7faa16fece -.->|targets| Windows
b663b684-a80f-4570-89b6-2f7faa16fece -.->|targets| Office365
b663b684-a80f-4570-89b6-2f7faa16fece -.->|targets| MicrosoftSharePoint
b663b684-a80f-4570-89b6-2f7faa16fece -.->|targets| OutlookWebAccess
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84 -.->|targets| Windows
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84 -.->|targets| Office365
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84 -.->|targets| Android
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84 -.->|targets| iOS
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| Windows
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| Office365
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| Android
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| iOS
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| Github
1a68b5eb-0112-424d-a21f-88dda0b6b8df -.->|targets| Gitlab
6a7a493a-511a-4c9d-aa9c-4427c832a322 -.->|targets| EULogin
6a7a493a-511a-4c9d-aa9c-4427c832a322 -.->|targets| Android
6a7a493a-511a-4c9d-aa9c-4427c832a322 -.->|targets| iOS
4a807ac4-f764-41b1-ae6f-94239041d349 -.->|targets| Android
4a807ac4-f764-41b1-ae6f-94239041d349 -.->|targets| iOS
4a807ac4-f764-41b1-ae6f-94239041d349 -.->|targets| EULogin
4a807ac4-f764-41b1-ae6f-94239041d349 -.->|targets| AzureAD
4a807ac4-f764-41b1-ae6f-94239041d349 -.->|targets| Office365
APT29 -.-> |performs| 06c60af1-5fa8-493c-bf9b-6b2e215819f1
UNC2452 -.-> |performs| 06c60af1-5fa8-493c-bf9b-6b2e215819f1
APT29 -.-> |performs| 58b98d75-fc63-4662-8908-a2a7f4200902
UNC2452 -.-> |performs| 58b98d75-fc63-4662-8908-a2a7f4200902
APT28 -.-> |performs| 2900d389-3098-49d3-8166-5b2612d03576
Kimsuky -.-> |performs| 2900d389-3098-49d3-8166-5b2612d03576
LazarusGroup -.-> |performs| 2900d389-3098-49d3-8166-5b2612d03576
MoonstoneSleet -.-> |performs| 2900d389-3098-49d3-8166-5b2612d03576
VoltTyphoon -.-> |performs| 2900d389-3098-49d3-8166-5b2612d03576
APT38 -.-> |performs| 0cdaee96-8595-4f3f-ba07-758b8be9d359
LazarusGroup -.-> |performs| 0cdaee96-8595-4f3f-ba07-758b8be9d359
APT28 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
APT29 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
UNC2452 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
FIN7 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
TA505 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
WizardSpider -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
UNC1878 -.-> |performs| b663b684-a80f-4570-89b6-2f7faa16fece
APT29 -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
UNC2452 -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
WizardSpider -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
UNC1878 -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
GamaredonGroup -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
APT28 -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
MustangPanda -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
RedDelta -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
TA505 -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
RomCom -.-> |performs| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
APT42 -.-> |performs| 1a68b5eb-0112-424d-a21f-88dda0b6b8df
LAPSUS$ -.-> |performs| 6a7a493a-511a-4c9d-aa9c-4427c832a322
LAPSUS -.-> |performs| 6a7a493a-511a-4c9d-aa9c-4427c832a322
APT29 -.-> |performs| 6a7a493a-511a-4c9d-aa9c-4427c832a322
UNC2452 -.-> |performs| 6a7a493a-511a-4c9d-aa9c-4427c832a322
APT29 -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
UNC2452 -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
SandwormTeam -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
GreyEnergy -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
Chimera -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
Kimsuky -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
TA406 -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
LAPSUS$ -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349
LAPSUS -.-> |performs| 4a807ac4-f764-41b1-ae6f-94239041d349

c4456134-df7b-4969-b5ff-a24794996890 -->|implements| 06c60af1-5fa8-493c-bf9b-6b2e215819f1
c4456134-df7b-4969-b5ff-a24794996890 -->|succeeds| 58b98d75-fc63-4662-8908-a2a7f4200902
2900d389-3098-49d3-8166-5b2612d03576 -->|succeeds| 06c60af1-5fa8-493c-bf9b-6b2e215819f1
2900d389-3098-49d3-8166-5b2612d03576 -->|succeeds| 58b98d75-fc63-4662-8908-a2a7f4200902
2900d389-3098-49d3-8166-5b2612d03576 -->|succeeds| 0cdaee96-8595-4f3f-ba07-758b8be9d359
cc9003f7-a9e3-4407-a1ca-d514af469787 -->|succeeds| 06c60af1-5fa8-493c-bf9b-6b2e215819f1
cc9003f7-a9e3-4407-a1ca-d514af469787 -->|enabling| b663b684-a80f-4570-89b6-2f7faa16fece
58b98d75-fc63-4662-8908-a2a7f4200902 -->|implements| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84
1a68b5eb-0112-424d-a21f-88dda0b6b8df -->|preceeds| 0cdaee96-8595-4f3f-ba07-758b8be9d359
dd5d942c-bac4-4000-b9a6-ca4fef6cfb84 -->|preceeds| 0cdaee96-8595-4f3f-ba07-758b8be9d359
6a7a493a-511a-4c9d-aa9c-4427c832a322 -->|preceeds| 0cdaee96-8595-4f3f-ba07-758b8be9d359
6a7a493a-511a-4c9d-aa9c-4427c832a322 -->|implements| 4a807ac4-f764-41b1-ae6f-94239041d349
b663b684-a80f-4570-89b6-2f7faa16fece -->|succeeds| dd5d942c-bac4-4000-b9a6-ca4fef6cfb84

```


<details>
<summary>Expand chaining data</summary>

| ☣️ Vector                                                                                                                                                                                                                                                                                                                                                                                                            | ⛓️ Link                 | 🎯 Target                                                                                                                                                                                                                                                                                             | ⛰️ Terrain                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | 🗡️ ATT&CK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Impersonate IT support via a spoofed phone call to deceive a victim and gain a remote access](../Threat%20Vectors/☣️%20Impersonate%20IT%20support%20via%20a%20spoofed%20phone%20call%20to%20deceive%20a%20victim%20and%20gain%20a%20remote%20access.md 'IT support impersonation via spoofed phone calls is a common socialengineering technique used by attackers to gain initial access to anorganisations n...') | `atomicity::implements` | [Social engineering attack using Microsoft Teams](../Threat%20Vectors/☣️%20Social%20engineering%20attack%20using%20Microsoft%20Teams.md 'Adversaries are using compromised Microsoft 365 tenants to create technicalsupport-themed domains and send tech support lures via Microsoft Teams, att...') | Attacker has compromised a valid Microsoft 365 tenant to host the lures, and valid valid credentials in targeted M365 tenant too. Targeted organizations must use an app like Microsoft Authenticator as second factor (app taking the code received after successful authentication granted by  the victim, the user, in previous step).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses ')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [Impersonate IT support via a spoofed phone call to deceive a victim and gain a remote access](../Threat%20Vectors/☣️%20Impersonate%20IT%20support%20via%20a%20spoofed%20phone%20call%20to%20deceive%20a%20victim%20and%20gain%20a%20remote%20access.md 'IT support impersonation via spoofed phone calls is a common socialengineering technique used by attackers to gain initial access to anorganisations n...') | `sequence::succeeds`    | [Spearphishing with an attachment extension .rdp](../Threat%20Vectors/☣️%20Spearphishing%20with%20an%20attachment%20extension%20.rdp.md 'Spearphishing with an attachment extension rdp refers to a targetedcyberattack where a malicious actor sends an email containing a filewith the file e...') | A threat actor relies on an email attachment lure. In this case a malicious file is masquerading as a RDP file in an attempt to deceive a victim about their identity and true nature of the file. The spear-phishing attachment provides a threat actor an initial access to the system.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | [T1566.001 : Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe'), [T1204.002 : User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002 'An adversary may rely upon a user opening a malicious file in order to gain execution Users may be subjected to social engineering to get them to open'), [T1036 : Masquerading](https://attack.mitre.org/techniques/T1036 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users andor security tools Masquerading ')                                                                                                                                                                                                                                                                                                                                              |
| [Azure - Gather User Information](../Threat%20Vectors/☣️%20Azure%20-%20Gather%20User%20Information.md 'This technique describes how adversaries obtain information about user accounts in Azure Active Directory AAD, which can be leveraged for further atta...')                                                                                                                                                   | `sequence::succeeds`    | [Social engineering attack using Microsoft Teams](../Threat%20Vectors/☣️%20Social%20engineering%20attack%20using%20Microsoft%20Teams.md 'Adversaries are using compromised Microsoft 365 tenants to create technicalsupport-themed domains and send tech support lures via Microsoft Teams, att...') | Attacker has compromised a valid Microsoft 365 tenant to host the lures, and valid valid credentials in targeted M365 tenant too. Targeted organizations must use an app like Microsoft Authenticator as second factor (app taking the code received after successful authentication granted by  the victim, the user, in previous step).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses ')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [Azure - Gather User Information](../Threat%20Vectors/☣️%20Azure%20-%20Gather%20User%20Information.md 'This technique describes how adversaries obtain information about user accounts in Azure Active Directory AAD, which can be leveraged for further atta...')                                                                                                                                                   | `sequence::succeeds`    | [Spearphishing with an attachment extension .rdp](../Threat%20Vectors/☣️%20Spearphishing%20with%20an%20attachment%20extension%20.rdp.md 'Spearphishing with an attachment extension rdp refers to a targetedcyberattack where a malicious actor sends an email containing a filewith the file e...') | A threat actor relies on an email attachment lure. In this case a malicious file is masquerading as a RDP file in an attempt to deceive a victim about their identity and true nature of the file. The spear-phishing attachment provides a threat actor an initial access to the system.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | [T1566.001 : Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe'), [T1204.002 : User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002 'An adversary may rely upon a user opening a malicious file in order to gain execution Users may be subjected to social engineering to get them to open'), [T1036 : Masquerading](https://attack.mitre.org/techniques/T1036 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users andor security tools Masquerading ')                                                                                                                                                                                                                                                                                                                                              |
| [Azure - Gather User Information](../Threat%20Vectors/☣️%20Azure%20-%20Gather%20User%20Information.md 'This technique describes how adversaries obtain information about user accounts in Azure Active Directory AAD, which can be leveraged for further atta...')                                                                                                                                                   | `sequence::succeeds`    | [Social engineering without attachment or URL](../Threat%20Vectors/☣️%20Social%20engineering%20without%20attachment%20or%20URL.md 'TOAD Telephone-Oriented Attack Delivery and BEC Business Email Compromise attacks are sophisticated forms of social engineering that pose significant ...')       | Adversary must have access to legitimate email accounts or impersonate authority  figures to trick victims into disclosing sensitive information or transferring funds.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [T1589.001 : Gather Victim Identity Information: Credentials](https://attack.mitre.org/techniques/T1589/001 'Adversaries may gather credentials that can be used during targeting Account credentials gathered by adversaries may be those directly associated with')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [Lateral movement via a compromised Teams account](../Threat%20Vectors/☣️%20Lateral%20movement%20via%20a%20compromised%20Teams%20account.md 'Lateral movement refers to attackers exploiting compromised accounts or systems to navigate through a network and gain access to sensitive resources I...')                                                                                                             | `sequence::succeeds`    | [Social engineering attack using Microsoft Teams](../Threat%20Vectors/☣️%20Social%20engineering%20attack%20using%20Microsoft%20Teams.md 'Adversaries are using compromised Microsoft 365 tenants to create technicalsupport-themed domains and send tech support lures via Microsoft Teams, att...') | Attacker has compromised a valid Microsoft 365 tenant to host the lures, and valid valid credentials in targeted M365 tenant too. Targeted organizations must use an app like Microsoft Authenticator as second factor (app taking the code received after successful authentication granted by  the victim, the user, in previous step).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | [T1199 : Trusted Relationship](https://attack.mitre.org/techniques/T1199 'Adversaries may breach or otherwise leverage organizations who have access to intended victims Access through trusted third party relationship abuses ')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [Lateral movement via a compromised Teams account](../Threat%20Vectors/☣️%20Lateral%20movement%20via%20a%20compromised%20Teams%20account.md 'Lateral movement refers to attackers exploiting compromised accounts or systems to navigate through a network and gain access to sensitive resources I...')                                                                                                             | `support::enabling`     | [Abuse of Microsoft Office Applications](../Threat%20Vectors/☣️%20Abuse%20of%20Microsoft%20Office%20Applications.md 'An employee named receives an email that appears to be from a trusted business partner or colleague The email contains an office document The end-user...')                     | Target systems must have Microsoft Office applications installed with macros  enabled or be susceptible to social engineering tactics that prompt users  to enable macros or execute malicious content.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [T1059.005 : Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005 'Adversaries may abuse Visual Basic VB for execution VB is a programming language created by Microsoft with interoperability with many Windows technolo'), [T1204.002 : User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002 'An adversary may rely upon a user opening a malicious file in order to gain execution Users may be subjected to social engineering to get them to open'), [T1137 : Office Application Startup](https://attack.mitre.org/techniques/T1137 'Adversaries may leverage Microsoft Office-based applications for persistence between startups Microsoft Office is a fairly common application suite on'), [T1203 : Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203 'Adversaries may exploit software vulnerabilities in client applications to execute code Vulnerabilities can exist in software due to unsecure coding p')                                                                  |
| [Spearphishing with an attachment extension .rdp](../Threat%20Vectors/☣️%20Spearphishing%20with%20an%20attachment%20extension%20.rdp.md 'Spearphishing with an attachment extension rdp refers to a targetedcyberattack where a malicious actor sends an email containing a filewith the file e...')                                                                                                                 | `atomicity::implements` | [Spearphishing Attachment](../Threat%20Vectors/☣️%20Spearphishing%20Attachment.md 'Spearphishing messages are often crafted using pernicious social engineeringtechniquesIn Spearphishing Attachment attacks, recipients receive emails t...')                                                       | Spear phishing requires more preparation and time to achieve success  than a phishing attack. That is because spear-phishing attackers attempt to obtain vast amounts of personal information about their victims.   Attackers can get the personal information they need using different ways:   - to compromise an email or messaging system trough other means, - to use OSINT, sourcing Social Media or glean personal information from the user's online presence. They want to craft emails that look as legitimate and attractive as possible  to increase the chances of fooling their targets, for instance sending a malicious  attachment where the filename references a topic the recipient is interested in. The highly personalized nature of spear-phishing attacks makes it more  difficult to identity than widescale phishing attacks. | [T1566.001 : Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [Social engineering without attachment or URL](../Threat%20Vectors/☣️%20Social%20engineering%20without%20attachment%20or%20URL.md 'TOAD Telephone-Oriented Attack Delivery and BEC Business Email Compromise attacks are sophisticated forms of social engineering that pose significant ...')                                                                                                                       | `sequence::preceeds`    | [Spearphishing Link](../Threat%20Vectors/☣️%20Spearphishing%20Link.md 'Adversaries may send spearphishing emails with a malicious link in anattempt to gain access to victim systems This sub-technique employsthe use of lin...')                                                                   | Spear phishing requires more preparation and time to achieve success than a phishing attack. That is because spear-phishing attackers attempt to obtain vast amounts of personal information about their victims,   the entities their work for, or their areas of interest.    Attackers can get the personal information they need using different ways: to compromise an email or messaging system trough other means, to use OSINT, scouring Social Media or glean personal information from the user's online presence.                                                                                                                                                                                                                                                                                                                              | [T1566.002 : Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002 'Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems Spearphishing with a link is a specific'), [T1036 : Masquerading](https://attack.mitre.org/techniques/T1036 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users andor security tools Masquerading '), [T1656 : Impersonation](https://attack.mitre.org/techniques/T1656 'Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf For e')                                                                                                                                                                                                                                                                                                                                                                             |
| [Social engineering without attachment or URL](../Threat%20Vectors/☣️%20Social%20engineering%20without%20attachment%20or%20URL.md 'TOAD Telephone-Oriented Attack Delivery and BEC Business Email Compromise attacks are sophisticated forms of social engineering that pose significant ...')                                                                                                                       | `sequence::preceeds`    | [Spearphishing Attachment](../Threat%20Vectors/☣️%20Spearphishing%20Attachment.md 'Spearphishing messages are often crafted using pernicious social engineeringtechniquesIn Spearphishing Attachment attacks, recipients receive emails t...')                                                       | Spear phishing requires more preparation and time to achieve success  than a phishing attack. That is because spear-phishing attackers attempt to obtain vast amounts of personal information about their victims.   Attackers can get the personal information they need using different ways:   - to compromise an email or messaging system trough other means, - to use OSINT, sourcing Social Media or glean personal information from the user's online presence. They want to craft emails that look as legitimate and attractive as possible  to increase the chances of fooling their targets, for instance sending a malicious  attachment where the filename references a topic the recipient is interested in. The highly personalized nature of spear-phishing attacks makes it more  difficult to identity than widescale phishing attacks. | [T1566.001 : Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [Social engineering without attachment or URL](../Threat%20Vectors/☣️%20Social%20engineering%20without%20attachment%20or%20URL.md 'TOAD Telephone-Oriented Attack Delivery and BEC Business Email Compromise attacks are sophisticated forms of social engineering that pose significant ...')                                                                                                                       | `sequence::preceeds`    | [SIM-card swapping](../Threat%20Vectors/☣️%20SIM-card%20swapping.md 'SIM swapping is a malicious technique where threat actors target mobile carriers to gain access tousers bank accounts, virtual currency accounts, and ...')                                                                     | Attacker must convince the mobile network operator (e.g. through social networking, forged identification, or insider attacks performed by trusted employees) to issue a new SIM card                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | [T1541 : Mobile : Foreground Persistence](https://attack.mitre.org/techniques/T1541 'Adversaries may abuse Androids startForeground API method to maintain continuous sensor access Beginning in Android 9, idle applications running in th')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [SIM-card swapping](../Threat%20Vectors/☣️%20SIM-card%20swapping.md 'SIM swapping is a malicious technique where threat actors target mobile carriers to gain access tousers bank accounts, virtual currency accounts, and ...')                                                                                                                                                                                     | `atomicity::implements` | [MFA Bypass Techniques](../Threat%20Vectors/☣️%20MFA%20Bypass%20Techniques.md 'MFA is a technique that requires more than one piece of evidence to authorize the user to access a resource If two pieces of evidence are needed to ve...')                                                           | Sufficient reconnaissance to identify a target account and MFA technologies being used.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [T1111](https://attack.mitre.org/techniques/T1111 'Adversaries may target multi-factor authentication MFA mechanisms, ie, smart cards, token generators, etc to gain access to credentials that can be us'), [T1621](https://attack.mitre.org/techniques/T1621 'Adversaries may attempt to bypass multi-factor authentication MFA mechanisms and gain access to accounts by generating MFA requests sent to usersAdver'), [T1566.001](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe'), [T1566.002](https://attack.mitre.org/techniques/T1566/002 'Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems Spearphishing with a link is a specific'), [T1566.004](https://attack.mitre.org/techniques/T1566/004 'Adversaries may use voice communications to ultimately gain access to victim systems Spearphishing voice is a specific variant of spearphishing It is ') |
| [Abuse of Microsoft Office Applications](../Threat%20Vectors/☣️%20Abuse%20of%20Microsoft%20Office%20Applications.md 'An employee named receives an email that appears to be from a trusted business partner or colleague The email contains an office document The end-user...')                                                                                                                                     | `sequence::succeeds`    | [Spearphishing Attachment](../Threat%20Vectors/☣️%20Spearphishing%20Attachment.md 'Spearphishing messages are often crafted using pernicious social engineeringtechniquesIn Spearphishing Attachment attacks, recipients receive emails t...')                                                       | Spear phishing requires more preparation and time to achieve success  than a phishing attack. That is because spear-phishing attackers attempt to obtain vast amounts of personal information about their victims.   Attackers can get the personal information they need using different ways:   - to compromise an email or messaging system trough other means, - to use OSINT, sourcing Social Media or glean personal information from the user's online presence. They want to craft emails that look as legitimate and attractive as possible  to increase the chances of fooling their targets, for instance sending a malicious  attachment where the filename references a topic the recipient is interested in. The highly personalized nature of spear-phishing attacks makes it more  difficult to identity than widescale phishing attacks. | [T1566.001 : Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems Spearphishing attachment is a spe')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

</details>
&nbsp; 


---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`📦 Delivery`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques resulting in the transmission of a weaponized object to the targeted environment.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`👤 End-user`](http://veriscommunity.net/enums.html#section-asset) : People - End-user

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 [` Microsoft Teams`](https://docs.microsoft.com/en-us/microsoftteams/) : Microsoft Teams is a proprietary business communication platform developed by Microsoft, as part of the Microsoft 365 family of products. Teams primarily competes with the similar service Slack, offering workspace chat and videoconferencing, file storage, and application integration.

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

 [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`♻️ Environment dependent`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Depends

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/
- [_2_] https://github.com/Octoberfest7/TeamsPhisher

[1]: https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/
[2]: https://github.com/Octoberfest7/TeamsPhisher

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


