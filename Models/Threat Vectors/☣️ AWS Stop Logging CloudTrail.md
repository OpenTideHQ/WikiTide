

# ☣️ AWS Stop Logging CloudTrail

🔥 **Criticality:Low** 🔫 : A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1562.008 : Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008 'An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection')



---

`🔑 UUID : d370aaea-c3e5-4d58-a6c9-3d1a7ffe50e3` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2024-10-31` **|** `🗓️ Last Modification : 2024-10-31` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> ### AWS Stop Logging CloudTrail Threat
> 
> The "AWS Stop Logging CloudTrail" threat is a malicious action where an attacker 
> deliberately disables AWS CloudTrail logging. This intentional act poses a significant 
> risk to AWS users, and understanding its nature, purpose, and implications is crucial 
> for maintaining and protecting CloudTrail logs.
> 
> ### Nature of the Threat
> 
> 1. **Definition**: It's an intentional act to stop AWS CloudTrail from recording 
> API activity and events within an AWS account.
> 2. **Method**: The attacker uses the AWS API, specifically the `StopLogging` operation 
> on a CloudTrail trail.
> 3. **Target**: The primary target is the CloudTrail service, which is responsible 
> for logging and monitoring AWS account activity.
> 
> ### Purpose and Motivation
> 
> 1. **Evasion**: The main goal is to evade detection by stopping the recording of 
> actions taken in the AWS environment.
> 2. **Concealment**: Attackers aim to hide their tracks and prevent their activities 
> from being logged.
> 3. **Persistence**: By disabling logging, attackers can maintain access and perform 
> actions without leaving a trail.
> 
> ### Potential Impact
> 
> 1. **Loss of Audit Trail**: Critical information about API calls and account activity 
> is no longer recorded.
> 2. **Compliance Violations**: Many regulatory standards require continuous logging, 
> which this threat violates.
> 3. **Increased Vulnerability**: Without logs, identifying and responding to other 
> security incidents becomes significantly harder.
> 4. **Extended Attacker Freedom**: Attackers can perform various malicious activities 
> without fear of being logged.
> 5. **Data Loss**: Any actions performed while logging is disabled are permanently 
> lost and cannot be retroactively captured.
> 
> ### Broader Implications
> 
> 1. **Part of Larger Attacks**: This action is often part of a more extensive attack 
> strategy, potentially indicating a sophisticated adversary.
> 2. **Indicator of Compromise**: The act of stopping CloudTrail logging is itself 
> a strong indicator that an account has been compromised.
> 3. **Time-Sensitive Impact**: Every moment CloudTrail logging remains disabled increases 
> the potential damage and loss of critical audit information.
> 
> ### Identifying the Threat
> 
> StopLogging is a critical action that adversaries may use to evade detection. By 
> halting the logging of their malicious activities, attackers aim to operate undetected 
> within a compromised AWS environment. Identifying such behavior is important, as 
> it signals an attempt to undermine the integrity of logging mechanisms, potentially 
> allowing malicious activities to proceed without observation. The impact of this 
> evasion tactic is significant, as it can severely hamper incident response and forensic 
> investigations by obscuring the attacker's actions.
> 



## 🖥️ Terrain 

 > A threat actor requires authenticated access with permissions 
> cloudtrail:StopLogging to execute the StopLogging API call.
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

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

  - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`☁️ IaaS`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` AWS` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`🔄 Log tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Log tampering or modification
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`🗿 Repudiation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action aimed at performing prohibited operations in a system that lacks the ability to trace the operations.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.
 - [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🤔 Unlikely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Improbable (improbably) - 20-45%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/stopping-cloudtrail-trail/
- [_2_] https://research.splunk.com/cloud/0b78a8f9-1d31-4d23-85c8-56ad13d5b4c1/

[1]: https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/stopping-cloudtrail-trail/
[2]: https://research.splunk.com/cloud/0b78a8f9-1d31-4d23-85c8-56ad13d5b4c1/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


