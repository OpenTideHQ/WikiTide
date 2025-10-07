

# ☣️ Scheduled tasks created with command line

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1053.005 : Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code There are multiple wa')



---

`🔑 UUID : 2b560980-d4c6-428c-963f-697e7e29938c` **|** `🏷️ Version : 4` **|** `🗓️ Creation Date : 2022-12-09` **|** `🗓️ Last Modification : 2022-12-13` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Adversaries can use  Windows Command Shell (cmd.exe) to execute specific commands 
> to create scheduled tasks for the purposes of dwelling, execution of binaries, 
> or for communication to Command and Control server infrastructure.
> 
> 
> Examples for creation of a scheduled task via command-line interface:
> 
> 1. Create a daily task to run at specific time:
> 
>    SCHTASKS /CREATE /SC DAILY /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM
> 
> The folder path before the task name, under the /TN option, is not a requirement, 
> but it'll help to keep the tasks separated. If the path is not specified, the task 
> will be created inside the Task Scheduler Library folder.
> 
> 2. Create a weekly task to run at specific time:
> 
>   SCHTASKS /CREATE /SC WEEKLY /D SUN /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM
> 
> 3. Create monthly task to run at specific time:
> 
>   SCHTASKS /CREATE /SC MONTHLY /D 15 /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM
> 
> 4. Create a scheduled task that runs daily as a specific user:
> 
>   SCHTASKS /CREATE /SC DAILY /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM
> 
> Parameters that can be used in creation scheduled task command:
> 
>  /CREATE - specifies the creation a new automated routine task
>  /SC - define the schedule of the task, for example it can include
>  MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE, and ONEVENT.
>  /D — specifies the day of the week to execute the task. (examples MON, TUE and etc)
>  /TN — specifies the task name and location, the task can be created in a specific
>  location directory (example /TN "FOLDERPATH\TASKNAME")
>  /ST — defines the time to run the task (in 24 hours format)
>  /RU — specifies the task to run under a specific user account.
>  /QUERY — displays all the system tasks.
> 



## 🖥️ Terrain 

 > An adversary has gained control over a Windows endpoint and has  
> privileges to create scheduled tasks using the command line.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Aliases                                                                                                               | Source                     | Sighting               | Reference                |
|:-------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] TA505 | [TA505](https://attack.mitre.org/groups/G0092) is a cyber criminal group that has been active since at least 2014. [TA505](https://attack.mitre.org/groups/G0092) is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving [Clop](https://attack.mitre.org/software/S0611).(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 June 2018)(Citation: Proofpoint TA505 Jan 2019)(Citation: NCC Group TA505)(Citation: Korean FSI TA505 2020) | CHIMBORAZO, Hive0065, Spandex Tempest                                                                                 | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| TA505              | TA505, the name given by Proofpoint, has been in the cybercrime business for at least four years. This is the group behind the infamous Dridex banking trojan and Locky ransomware, delivered through malicious email campaigns via Necurs botnet. Other malware associated with TA505 include Philadelphia and GlobeImposter ransomware families.                                                                                                                                                                                  | SectorJ04, SectorJ04 Group, GRACEFUL SPIDER, GOLD TAHOE, Dudear, G0092, ATK103, Hive0065, CHIMBORAZO, Spandex Tempest | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

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
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🖲️ Input/Output Server`](https://collaborate.mitre.org/attackics/index.php/Input/Output_Server) : The Input/Output (I/O) server provides the interface between the control system LAN applications and the field equipment monitored and controlled by the control system applications. The I/O server, sometimes referred to as a Front-End Processor (FEP) or Data Acquisition Server (DAS), converts the control system application data into packets that are transmitted over various types of communications media to the end device locations. The I/O server also converts data received from the various end devices over different communications mediums into data formatted to communicate with the control system networked applications.
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Desktop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Desktop or workstation
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access
 - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

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

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.

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

- [_1_] https://redcanary.com/threat-detection-report/techniques/scheduled-task/
- [_2_] https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/use-at-command-to-schedule-tasks
- [_3_] https://attack.mitre.org/techniques/T1053/005/
- [_4_] https://attack.mitre.org/software/S0111/
- [_5_] https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
- [_6_] https://www.windowscentral.com/how-create-task-using-task-scheduler-command-prompt

[1]: https://redcanary.com/threat-detection-report/techniques/scheduled-task/
[2]: https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/use-at-command-to-schedule-tasks
[3]: https://attack.mitre.org/techniques/T1053/005/
[4]: https://attack.mitre.org/software/S0111/
[5]: https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
[6]: https://www.windowscentral.com/how-create-task-using-task-scheduler-command-prompt

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


