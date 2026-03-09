

# ☣️ Linux kernel module injection from container

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1547.006 : Boot or Logon Autostart Execution: Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006 'Adversaries may modify the kernel to automatically execute programs on system boot Loadable Kernel Modules LKMs are pieces of code that can be loaded ')



---

`🔑 UUID : dcccd7e5-9d3f-4b36-853a-5cd18a7ef752` **|** `🏷️ Version : 2` **|** `🗓️ Creation Date : 2023-01-09` **|** `🗓️ Last Modification : 2023-01-10` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Loadable Kernel Modules (LKM) can be used by adversaries to deliver 
> sophisticated and hard to detect rootkits. Each event where kernel modules 
> are loaded from a container should be investigated with the exeption of 
> Security tools deployed in containers.
> 
> An injected kernel module is just code execution, and can in theory do 
> more or less anything, but threat actors mostly use this for dwelling and 
> for hiding their presence on a system.
> 



## 🖥️ Terrain 

 > Threat actor has already escalated privileges to root via an exploit on a 
> unprivileged container host, or the threat actor exploited an application 
> running in a highly privileged container, which means a host running 
> highly privileged containers with CAP_NET_ADMIN or CAP_SYS_MODULE 
> capabilities or Kubernetes pods running in privileged mode. 
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🏃🏽 Defense Evasion`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques an attacker may specifically use for evading detection or avoiding other defenses.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

  - `🔧 Embedded` : Firmware, middleware and low level software running on devices which are typically not manageable by the consumer.
 - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Compute Cluster`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🛠️ Microservices`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖥️ Virtual Machines Host`](http://veriscommunity.net/enums.html#section-asset) : Server - Virtual Host

---

#### **💿 Platforms concerned [DEPRECATED]**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Linux` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`⚠️ Significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`🗿 Repudiation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at performing prohibited operations in a system that lacks the ability to trace the operations.
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`♻️ Environment dependent`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Depends

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.giac.org/paper/gsec/935/kernel-rootkits/101864
- [_2_] https://www.zdnet.com/article/this-new-linux-malware-has-a-sneaky-way-of-staying-hidden/
- [_3_] https://github.com/milabs/awesome-linux-rootkits
- [_4_] https://www.debian.org/doc/manuals/securing-debian-manual/ch10s04.en.html

[1]: https://www.giac.org/paper/gsec/935/kernel-rootkits/101864
[2]: https://www.zdnet.com/article/this-new-linux-malware-has-a-sneaky-way-of-staying-hidden/
[3]: https://github.com/milabs/awesome-linux-rootkits
[4]: https://www.debian.org/doc/manuals/securing-debian-manual/ch10s04.en.html

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


