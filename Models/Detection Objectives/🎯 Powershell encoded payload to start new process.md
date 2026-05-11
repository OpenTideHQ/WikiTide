

# 🎯 Powershell encoded payload to start new process

**🚩 Priority : `High`**

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.

🗡️ **ATT&CK Techniques** :  [T1027.010 : Obfuscated Files or Information: Command Obfuscation](https://attack.mitre.org/techniques/T1027/010 'Adversaries may obfuscate content during command execution to impede detection Command-line obfuscation is a method of making strings and patterns wit'), [T1059 : Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries These interfaces and languages provide ways of interac'), [T1059.001 : Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001 'Adversaries may abuse PowerShell commands and scripts for execution PowerShell is a powerful interactive command-line interface and scripting environm'), [T1140 : Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140 'Adversaries may use Obfuscated Files or InformationhttpsattackmitreorgtechniquesT1027 to hide artifacts of an intrusion from analysis They may require'), [T1068 : Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges Exploitation of a software vulnerability occurs when an adversary')

---

`🔑 UUID : bfeb24bf-8a17-4ccc-8aec-91721743153d` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2026-03-24` **|** `🗓️ Last Modification : 2026-03-24` **|** `👩‍💻 Model author : None` **|** `👥 Contributors : None` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : dom::1.0`

## 💡 Objective

**🏷️ Type** : Threat - Alerts meant for detection cybersecurity threats, and which should eventually trigger Incident Response  

> Detect and alert on powershell encoded payload to start new process activity.
> 
> This detection objective was migrated from a Cyber Detection Model (CDM).
> 

**🎼 Composition** : Independent - No composition performed, each signal can be treated as independent, unrelated alerts.

> Each signal triggers independently, covering different detection approaches for the same objective.


### 🌊 Related OpenTide Objects


```mermaid

mindmap
Root[🎯 Powershell encoded payload to start new process]
    
      📡 Powershell encoded payload to start new process 
      ☣️ Powershell with encoded payload passed to cmdline 


```


**Threats**

| ☣️ Threat Vectors                                                                                                                                                                                                                                                                                       |
|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Powershell with encoded payload passed to cmdline](../Threat%20Vectors/☣️%20Powershell%20with%20encoded%20payload%20passed%20to%20cmdline 'When working with PowerShell, a threat actor can encode a command or scriptusing Base64 or other type of encoding and pass it as a parameter to thecom...') |

**Rules**

| 📡 Detection Objective Signals                                                                                                                                                                                                                                   | 🚨 Detection Rules    |
|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|
| [Powershell encoded payload to start new process](#powershell-encoded-payload-to-start-new-process 'Adversaries use PowerShell to execute local scripts and execute remote resourcesafter retrieving them using multiple network protocols They can also e...') | ❌ No Detection Rules |

## 📡 Signals


### Powershell encoded payload to start new process

🪪 **UUID** : `cf9c69a2-9317-4f0f-9506-fbeeb1c73ff0`

> Adversaries use PowerShell to execute local scripts and execute remote resources
after retrieving them using multiple network protocols. They can also encode payloads
using the command line and load PowerShell into other processes.

Here are some examples of encoded PowerShell payloads and how they can be detected:

### Base64-Encoded Payload

#### background

A common technique is to encode the entire PowerShell script in Base64 and execute it using
the -encodedcommand switch.

To detect this, look for:
- Execution of powershell.exe with encode arguments
- The presence of base64 string in the command line

#### detection strategies

to detect base64encoded string, you may use REGEX and then you may have the
option on the detection platform to decode the base64 encoded string to
confirm the actions done.

When focusing on specific keywords within the encoded string, a very good
approach is to precompute the base64 encoded version of the keyword and
search for that pattern in strings. To precompute the base64 string, 3
scenario have to be considered:
- the keyword is at a boundary of a 3-character block
- the keyword starts at second character of a 3-character block
- the keyword starts at the third character of 3-character block

Malicious payloads are often encoded and obfuscated, with PowerShell commands frequently
used to download them from the internet. To detect encoded and downloadable command line
arguments, it is essential to examine PowerShell logs, such as Sysmon or Windows PowerShell logs,
for the presence of specific keywords like "Net.WebClient," "DownloadFile," "Invoke-WebRequest,"
"Invoke-Shellcode," "http:," "-enc," "-encodedCommand," "-e," "-ec," "-en," "-encod," and "-enco".

Additionally, you can visit the following page to access a PowerShell Watchlist that helps with detection. [4]

For example, this CDM attemtps to detect the launch of a process
using the cmdlet "Start-Process". Preprocessing this keyword gives
the following search strings (without decoding base64 nor REGEX)

| Keyword | offset | string (with leading _ or *) | search string |
| --- | --- | --- | --- |
| Start-Process | 0 | U3RhcnQtUHJvY2Vzcw== | U3RhcnQtUHJvY2Vz |
| Start-Process | 1 | X1N0YXJ0LVByb2Nlc3M= / KlN0YXJ0LVByb2Nlc3M= | N0YXJ0LVByb2Nl |
| Start-Process | 2 | X19TdGFydC1Qcm9jZXNz / KipTdGFydC1Qcm9jZXNz | TdGFydC1Qcm9jZXNz |

### Obfuscated Payload with Special Characters

Adversaries may also obfuscate the PowerShell script using special characters.

To detect this, look for:
- Execution of powershell.exe with the -nop, -w hidden, and -c arguments
- High counts of obfuscation characters like `, `, and '

Useful telemetry will include:

- Windows Security Event ID 400: PowerShell command-line logging
- Windows Security Event IDs 800 and 4103: Module loading and Add-Type logging
- Windows Security Event ID 4688 : A new process has been created including process command-line
- Sysmon Event IDs 1 and 7: Process creation and Image loaded

Tuning considerations:
- Monitor for any attempts to enable scripts running on a system would be considered suspicious.
If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching
or other administrator functions are suspicious. Scripts should be captured from the file system when
possible to determine their actions and intent.
- Monitor for newly executed processes that may abuse PowerShell commands and scripts for execution.
PowerShell is a scripting environment included with Windows that is used by both attackers and administrators.
Execution of PowerShell scripts in most Windows versions is opaque and not typically secured by antivirus
which makes using PowerShell an easy way to circumvent security measures.
- Encoded PowerShell can be abused to avoid any complexity with special characters that can be difficult
to handle.


**🔎 Data Visibility**

- **Availability** : Unknown
- **Requirements** : `Data collection: Carbon Black EDR Connectors, Sysmon Logs, Windows Security Logs.
Data sources: Command, File, Script, Module, Process.
`

_💾 Possible logsources_

_❌ No logsources mentioned_

**🧲 Related Entities**

| Name    | Category                                  | Description                                                                                       |
|:--------|:------------------------------------------|:--------------------------------------------------------------------------------------------------|
| Process | **Host Entities** : Host Related Entities | Represents a running process on a host, including its attributes likeprocess ID and command line. |

**⚠️ Detectors**

_❌ No detectors mentioned_

**🌐 Examples**

_❌ No examples mentioned_



## References



**🕊️ Publicly available resources**

- [_1_] https://www.leeholmes.com/searching-for-content-in-base-64-strings/
- [_2_] https://research.splunk.com/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/
- [_3_] https://www.gigasheet.com/post/powershell-threat-hunting-made-easy
- [_4_] https://github.com/secprentice/PowerShellWatchlist/blob/master/badshell.txt

[1]: https://www.leeholmes.com/searching-for-content-in-base-64-strings/
[2]: https://research.splunk.com/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/
[3]: https://www.gigasheet.com/post/powershell-threat-hunting-made-easy
[4]: https://github.com/secprentice/PowerShellWatchlist/blob/master/badshell.txt

