

# ☣️ Non-Approved container image deployed to run cryptominer

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1610 : Deploy Container](https://attack.mitre.org/techniques/T1610 'Adversaries may deploy a container into an environment to facilitate execution or evade defenses In some cases, adversaries may deploy a new container'), [T1525 : Implant Internal Image](https://attack.mitre.org/techniques/T1525 'Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment Amazon Web Servi'), [T1496 : Resource Hijacking](https://attack.mitre.org/techniques/T1496 'Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system andor hosted service availabi')



---

`🔑 UUID : eca91e9a-616f-4439-ac03-5d0ecc2266df` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2022-06-29` **|** `🗓️ Last Modification : 2022-06-29` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> A threat actor can gain access to deployment workflows and pipelines and can then abuse acquired access to deploy images of their own choosing to deploy a cryptominer either directly via a malicious image, or by deploying a clean image first and then a cryptominer and C2 Infrastructure



## 🖥️ Terrain 

 > Running container clusters running in cloud, private cloud or in Enterprise Data Centre environments, potentially connected via a Continuous deployment tool

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

  - `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.
 - `☁️ Private Cloud` : Infrastructure hosted at a third party, but based on custom specification and managed on a platform level.
 - `🏢 Enterprise` : Generic databases, applications, machines and systems that are usually on premises or on Cloud traditional VMs.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🛠️ CI/CD Pipelines`](http://veriscommunity.net/enums.html#section-asset) : CI/CD pipelines automate the process of building, testing, and deploying software, ensuring efficient and reliable software delivery.
 - [`🖥️ Compute Cluster`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🛠️ Development Pipelines`](http://veriscommunity.net/enums.html#section-asset) : Development pipelines outline the stages and workflows involved in the software development process, from initial development to testing, integration, and deployment.

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - [` AWS EC2`](https://docs.aws.amazon.com/ec2/index.html) : Amazon Elastic Compute Cloud (Amazon EC2) is a web service that provides resizable computing capacity—literally, servers in Amazon's data centers—that you use to build and host your software systems.
 - [` AWS EKS`](https://docs.aws.amazon.com/eks/index.html) : Amazon Elastic Kubernetes Service (Amazon EKS) is a managed service that makes it easy for you to run Kubernetes on AWS without needing to install and operate your own Kubernetes clusters.
 - [` AWS ECS`](https://docs.aws.amazon.com/ecs/index.html) : Amazon Elastic Container Service (Amazon ECS) is a highly scalable, fast, container management service that makes it easy to run, stop, and manage Docker containers on a cluster of Amazon EC2 instances.
 - [` AWS Fargate`](https://docs.aws.amazon.com/AmazonECS/latest/userguide/what-is-fargate.html) : AWS Fargate is a technology that you can use with Amazon ECS to run containers without having to manage servers or clusters of Amazon EC2 instances.
 - [` Azure AKS`](https://docs.microsoft.com/en-us/azure/aks/) : AKS allows you to quickly deploy a production ready Kubernetes cluster in Azure. Learn how to use AKS with these quickstarts, tutorials, and samples.
 - [` VMware Tanzu`](https://docs.vmware.com/en/VMware-Tanzu/index.html) : Tanzu is a suite of products that helps users run and manage multiple Kubernetes (K8S) clusters across public and private clouds.
 - [` OVHcloud`](https://docs.ovh.com/gb/en/) : OVH, legally OVH Groupe SAS, is a French cloud computing company which offers VPS, dedicated servers and other web services.
 - [` IBM Cloud Kubernetes`](https://cloud.ibm.com/docs/containers?topic=containers-getting-started) : IBM Cloud Kubernetes Service is a managed offering to create your own Kubernetes cluster of compute hosts to deploy and manage containerized apps on IBM Cloud.
 - [` Oracle Container Engine`](https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) : Oracle Cloud Infrastructure Container Engine for Kubernetes is a fully-managed, scalable, and highly available service that you can use to deploy your containerized applications to the cloud.

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🔥 Substantial incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack which has a serious impact on a medium-sized organisation, or which poses a considerable risk to a large organisation or wider / local government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`💀 Infrastructure Compromise`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.
 - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🦹 Asset and fraud`](http://veriscommunity.net/enums.html#section-impact) : Asset and fraud-related losses
 - [`💲 Operating costs`](http://veriscommunity.net/enums.html#section-impact) : Increased operating costs
 - [`🩼 Impairement`](http://veriscommunity.net/enums.html#section-impact) : Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`♻️ Environment dependent`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Depends

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://www.securityweek.com/threat-actors-target-kubernetes-clusters-argo-workflows
- [_2_] https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment/
- [_3_] https://www.stackrox.io/blog/kubernetes-security-101/

[1]: https://www.securityweek.com/threat-actors-target-kubernetes-clusters-argo-workflows
[2]: https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment/
[3]: https://www.stackrox.io/blog/kubernetes-security-101/

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


