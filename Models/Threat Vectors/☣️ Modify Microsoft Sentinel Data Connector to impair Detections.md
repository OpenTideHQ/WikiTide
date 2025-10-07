

# ☣️ Modify Microsoft Sentinel Data Connector to impair Detections

🔥 **Criticality:Severe** 🚨 : A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1562.008 : Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008 'An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection')



---

`🔑 UUID : 48432b70-77c4-4f5a-9d66-75764c1777c6` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-12-08` **|** `🗓️ Last Modification : 2022-12-08` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> A threat actor may want to disable, remove or update the configuration of
> Sentinel Connectors to act invisibly in Azure, which would impair the ability
> of a SOC to receive alerts since it would stop log file ingestion into Azure
> Sentinel. 
> 
> An attacker can do this either by deploying via API an ARM template, biceps
> template, or other script/code element that can be used via Azure APIs,
> using the Azure CLI or directly on the portal itself via a browser.
> 



## 🖥️ Terrain 

 > Requires access to privileged Azure credentials
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

 `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🛠️ CI/CD Pipelines`](http://veriscommunity.net/enums.html#section-asset) : CI/CD pipelines automate the process of building, testing, and deploying software, ensuring efficient and reliable software delivery.
 - [`👤 System admin`](http://veriscommunity.net/enums.html#section-asset) : People - Administrator

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` Azure` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🚨 Highly significant incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

 [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

 [`🤬 Lose Capabilities`](http://veriscommunity.net/enums.html#section-impact) : Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`😅 Very Unlikely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Highly improbable - 05-20%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources

[1]: https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


