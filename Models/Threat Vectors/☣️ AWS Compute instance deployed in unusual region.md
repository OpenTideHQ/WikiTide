

# ☣️ AWS Compute instance deployed in unusual region

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1496 : Resource Hijacking](https://attack.mitre.org/techniques/T1496 'Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system andor hosted service availabi')



---

`🔑 UUID : 1040ebd2-4659-4844-9238-95fa69a7e63c` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-12-12` **|** `🗓️ Last Modification : 2022-12-12` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Certain threat actors will try to launch AWS compute instances 
> (EC2, EKS, ECS) instances to achieve their objectives
> 
> One of the main vectors currently is to monetize access to 
> privileged AWS credentials by deploying new compute instances of various types 
> to mine cryptocurrencies. To hide their deployed instances, a threat actor 
> may deploying the resources into unused regions, where they may go 
> unnoticed.
> 
> Additionally threat actor may launch compute instances to act as staging 
> platforms for serving malware for other campaigns.
> 
> It is expected that threat actors will potentially use compute instances 
> for other purposes than the 2 listed above.
> 



## 🖥️ Terrain 

 > Attacker needs to control credentials required to deploy an EC2 instance,
> or to deploy a compute resource of a type that runs on EC2.
> 

---

## 🕸️ Relations



### 🐲 Actors sightings 

| Actor                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Aliases     | Source                     | Sighting               | Reference                |
|:---------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------|:---------------------------|:-----------------------|:-------------------------|
| [Enterprise] TeamTNT | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021)                                                                                                                                                                                                    |             | 🗡️ MITRE ATT&CK Groups     | No documented sighting | No documented references |
| TeamTNT              | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim.They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware.TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany. | Adept Libra | 🌌 MISP Threat Actor Galaxy | No documented sighting | No documented references |

### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`💥 Impact`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques aimed at manipulating, interrupting or destroying the target system or data.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

 [`☁️ IaaS`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - [` AWS EC2`](https://docs.aws.amazon.com/ec2/index.html) : Amazon Elastic Compute Cloud (Amazon EC2) is a web service that provides resizable computing capacity—literally, servers in Amazon's data centers—that you use to build and host your software systems.
 - [` AWS ECS`](https://docs.aws.amazon.com/ecs/index.html) : Amazon Elastic Container Service (Amazon ECS) is a highly scalable, fast, container management service that makes it easy to run, stop, and manage Docker containers on a cluster of Amazon EC2 instances.
 - [` AWS EKS`](https://docs.aws.amazon.com/eks/index.html) : Amazon Elastic Kubernetes Service (Amazon EKS) is a managed service that makes it easy for you to run Kubernetes on AWS without needing to install and operate your own Kubernetes clusters.

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🔫 Localised incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification
 - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`💲 Operating costs`](http://veriscommunity.net/enums.html#section-impact) : Increased operating costs
 - [`🦹 Asset and fraud`](http://veriscommunity.net/enums.html#section-impact) : Asset and fraud-related losses
 - [`⚖️ Legal and regulatory`](http://veriscommunity.net/enums.html#section-impact) : Legal and regulatory costs

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e
- [_2_] https://www.techradar.com/news/upgraded-crypto-mining-malware-now-steals-aws-credentials
- [_3_] https://cybersecurityworldconference.com/2022/01/13/threat-actors-abuse-public-cloud-services-to-spread-multiple-rats/
- [_4_] https://sysdig.com/blog/teamtnt-aws-credentials/
- [_5_] https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Detecting_suspicious_new_instances_in_your_AWS_EC2_environment

[1]: https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e
[2]: https://www.techradar.com/news/upgraded-crypto-mining-malware-now-steals-aws-credentials
[3]: https://cybersecurityworldconference.com/2022/01/13/threat-actors-abuse-public-cloud-services-to-spread-multiple-rats/
[4]: https://sysdig.com/blog/teamtnt-aws-credentials/
[5]: https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Detecting_suspicious_new_instances_in_your_AWS_EC2_environment

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


