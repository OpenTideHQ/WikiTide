

# ☣️ Adversary abuses sudo elevation control mechanism

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1548 : Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548 'Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions Most modern systems contain native eleva')



---

`🔑 UUID : 422098a7-567e-47fe-9e92-9fd3ec6df768` **|** `🏷️ Version : 3` **|** `🗓️ Creation Date : 2022-10-27` **|** `🗓️ Last Modification : 2022-12-21` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Sudo is a command-line utility for Unix and Linux-based systems that can
> provide an effective way to give specific user permissions to run root
> (most powerful) level commands on the system. Unfortunately, some
> misconfigurations in sudo functionality can allow threat actors to escalate
> their privileges to root access.
> 
> If the file /etc/sudoers (used to store all sudo privileges) is modified
> this can grant to the attacker elevation of privileges. Attackers may use
> custom parameters with sudo to edit the sudoers file. For example -f or -l
> can be used to edit this file or list which commands or binaries the
> current user has access to run.
> 
> GTFOBins is a list of Unix binaries which is used by the threat actors to
> bypass local security restrictions in misconfigured systems. GTFOBins
> allows to search for binaries or commands whether they are executed as sudo
> and if they provide access to normally restricted actions. The repo list
> contains 300+ commands that could be abused for different purposes if not
> configured using this filter. The current list is an open collaborative
> project. Link: https://gtfobins.github.io/#+sudo
> 
> Examples: 
> 
> A "tar" option can be exploited to write to arbitrary files (works only for
> GNU tar). If write data to files, it may be used for privileged writes on
> the files ouside a restricted file system. A "tar" command can break out
> from restricted environments, using spawn of an interactive system shell.
> 
> Reference: https://gtfobins.github.io/gtfobins/tar/
> 
> tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
> 
> For GNU tar:
> tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
> 
> or (for GNU tar when limited command argument injection is available)
> 
> TF=$(mktemp)
> echo '/bin/sh 0<&1' > "$TF"
> tar cf "$TF.tar" "$TF"
> tar xf "$TF.tar" --to-command sh
> rm "$TF"*
> 
> The pkexec command can be exploited to gain a root shell and to access the
> file system, escalate or maintain privilege access. 
> 
> Reference: https://gtfobins.github.io/gtfobins/pkexec/
> 
> sudo pkexec /bin/sh
> 



## 🖥️ Terrain 

 > Threat actor needs root level access to edit the sudoers file.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🥸 Privilege Escalation`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : The result of techniques that provide an attacker with higher permissions on a system or network.

---

#### **🛰️ Domains [DEPRECATED]**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets [DEPRECATED]**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🕹️ Remote access`](http://veriscommunity.net/enums.html#section-asset) : Server - Remote access

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

  - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://steflan-security.com/linux-privilege-escalation-sudo-commands-binaries/
- [_2_] https://gtfobins.github.io/
- [_3_] https://gtfobins.github.io/gtfobins/tar/
- [_4_] https://gtfobins.github.io/gtfobins/pkexec/

[1]: https://steflan-security.com/linux-privilege-escalation-sudo-commands-binaries/
[2]: https://gtfobins.github.io/
[3]: https://gtfobins.github.io/gtfobins/tar/
[4]: https://gtfobins.github.io/gtfobins/pkexec/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


