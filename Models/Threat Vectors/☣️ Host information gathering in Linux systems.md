

# ☣️ Host information gathering in Linux systems

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1082 : System Information Discovery](https://attack.mitre.org/techniques/T1082 'An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and')



---

`🔑 UUID : 4f0f3e9c-8d61-422c-9c13-809aa75cab59` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-08-06` **|** `🗓️ Last Modification : 2025-08-07` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Host information gathering in Linux can be a part of a reconnaissance
> process, allowing threat actors to understand the target system details and
> configuration, collect valuable information and identify potential
> vulnerabilities on the host.  
> 
> ### Possible information gathering on Linux system
> 
> - A hostname and domain name - a threat actor may use the `hostname` command
>   to retrieve the system's hostname and domain name.
> - IP address: usage of `ip addr` or `ifconfig` commands can retrieve the
>   system's IP address. The IP address of the system is a valuable piece of
>   information for future collection and reconnaissance activities.
> - Network interface configuration: the command `ip link` or `ifconfig` is
>   used to retrieve information about network interfaces, including IP
>   addresses, subnet masks, and default gateways.
> - Operating system and version: a threat actor can use `uname -a` or
>   `cat /etc/os-release` command to retrieve information about the operating
>   system and its version. A command like `uname` can display information
>   about the system, for example the kernel name, version, and the Linux
>   architecture.  
> - Kernel Version: with the command `uname -r` an attacker can retrieve the
>   kernel version of a targeted system.
> - CPU architecture: a threat actor may use the `uname -m` command to
>   retrieve the CPU architecture. A threat actor may also use `lscpu` on Linux
>   to gather CPU's capabilities like model information, number of cores,
>   speeds, flags, virtualisation capabilities and other CPU related
>   parameters ref [3]. 
> - Memory and disk information: an attacker can use `-m` and `df -h` commands
>   to retrieve information about memory and disk usage. With other commands
>   like `df`, `fdisk`, or `mount` they can check the system storage and to
>   find the disks attached to the system ref [2], [3].  
> - Whois lookup: a threat actor can perform the command `whois` <domain_name>
>   to retrieve which are the registered domains in the database record on
>   the host.
> - Name server lookup: a threat actor can use `nslookup` on Linux to get the
>   information from a DNS server. It queries DNS to obtain a domain name, IP
>   address mapping, or any other DNS record. This coomand can be used for a
>   system gathering of information. 
> - Environment variables: `env` or `printenv` can expose environment
>   variables, which might include credentials, proxy settings, or session-
>   related tokens useful for further exploitation.
> - Running processes and services: commands like `ps aux`, `top` can help a
>   threat actor to identify active processes and services, which may reveal
>   misconfigured applications or listening services.
> - Scheduled jobs: `crontab -l`, `cat /etc/crontab`, or reviewing
>   `/etc/cron.*` directories can uncover automated tasks or persistence
>   mechanisms.
> - Listening ports and services: `ss -tuln` or `netstat -tuln` can show
>   services listening on the host, along with the associated ports and
>   protocols.  
>   
> ### Known tools used for Linux information gathering
> 
> - Nmap: A network scanning tool that can be used to gather information about
>   open ports and services.
> - LinEnum: A tool that can be used to gather information about Linux
>   systems, including user and group information.
> - Zenmap - it's a network discovery and security auditing tool
> - SPARTA - tool used in the scanning and enumeration phase of information
>   gathering on Linux systems. This tool can be used for network scanning and
>   collection of information, for example scan of IP ranges, network and
>   domain names ref [4]. 
> 



## 🖥️ Terrain 

 > A threat actor needs an initial access to a Linux system.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🔭 Reconnaissance`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Researching, identifying and selecting targets using active or passive reconnaissance.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Linux` : Placeholder

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

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🥸 Identity Theft`](http://veriscommunity.net/enums.html#section-impact) : Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.geeksforgeeks.org/linux-unix/kali-linux-information-gathering-tools
- [_2_] https://www.redhat.com/en/blog/linux-system-info-commands
- [_3_] https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502
- [_4_] https://www.geeksforgeeks.org/linux-unix/sparta-tool-in-kali-linux

[1]: https://www.geeksforgeeks.org/linux-unix/kali-linux-information-gathering-tools
[2]: https://www.redhat.com/en/blog/linux-system-info-commands
[3]: https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502
[4]: https://www.geeksforgeeks.org/linux-unix/sparta-tool-in-kali-linux

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


