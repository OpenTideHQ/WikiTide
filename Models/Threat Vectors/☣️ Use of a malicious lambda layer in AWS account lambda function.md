

# ☣️ Use of a malicious lambda layer in AWS account lambda function

🔥 **Criticality:Low** 🔫 : A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1648 : Serverless Execution](https://attack.mitre.org/techniques/T1648 'Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments Many cloud providers '), [T1195.001 : Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001 'Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromi')



---

`🔑 UUID : 2d3b113e-c6ad-492f-a6cb-1590a8d1191d` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-11-22` **|** `🗓️ Last Modification : 2022-11-23` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> A Lambda layer is an archive containing additional code, such as libraries,
> dependencies, or even custom runtimes that is are extract to the /opt directory in the execution environment of the function they are added to. While AWS provides a few layers, developers
> may also create custom ones to share in their organization, or use an external one
> by pointing to a particular ARN. Layers are immutable, meaning once they are
> created, a version is made and further changes would bump the version.
> A threat actor can compromise one or more lambda functions by centrally 
> compromising a lambda layer used by one or more other AWS accounts. This 
> can also be a third party lambda layer in use by EC accounts. 
> 
> Once a new version of a lambda layer exists, it can  get deployed 
> via some trigger+action needed on the side of the lambda administrator, 
> unless the threat actor controls credentials to deploy or update lambda 
> functions.
> 



## 🖥️ Terrain 

 > Requires that a threat actor can deploy code changes to a third party
> or an EC controlled/deployed lambda layer in use by EC account(s), or 
> that a threat actor can add a malicious lambda layer to a new or existing
> lambda function.
> 

---

## 🕸️ Relations



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

 `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`🔧 Serverless`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

 ` AWS Lambda` : Placeholder

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🔫 Localised incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`👽 Alter behavior`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Influence or alter human behavior
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`👁️‍🗨️ Information Disclosure`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to read a file that one was not granted access to, or to read data in transit.
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`⚙️ Modify configuration`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify configuration or services
 - [`✨ Modify data`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Modify stored data or content
 - [`🐒 Tampering`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🧠 IP Loss`](http://veriscommunity.net/enums.html#section-impact) : Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.
 - [`⚖️ Legal and regulatory`](http://veriscommunity.net/enums.html#section-impact) : Legal and regulatory costs
 - [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.
 - [`💲 Operating costs`](http://veriscommunity.net/enums.html#section-impact) : Increased operating costs

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e
- [_2_] https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
- [_3_] https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html
- [_4_] https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html
- [_5_] https://github.com/aws-amplify/amplify-cli/issues/6100
- [_6_] https://lukemiller.dev/blog/jest-test-with-lambda-layers-mocking-a-ote-layer/
- [_7_] https://medium.com/devops-techable/how-to-work-with-lambda-layers-352ddb32f345

[1]: https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e
[2]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
[3]: https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html
[4]: https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html
[5]: https://github.com/aws-amplify/amplify-cli/issues/6100
[6]: https://lukemiller.dev/blog/jest-test-with-lambda-layers-mocking-a-ote-layer/
[7]: https://medium.com/devops-techable/how-to-work-with-lambda-layers-352ddb32f345

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


