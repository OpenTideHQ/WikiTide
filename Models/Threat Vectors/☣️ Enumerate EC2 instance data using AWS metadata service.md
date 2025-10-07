

# ☣️ Enumerate EC2 instance data using AWS metadata service

🔥 **Criticality:Medium** ❗ : A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1119 : Automated Collection](https://attack.mitre.org/techniques/T1119 'Once established within a system or network, an adversary may use automated techniques for collecting internal data Methods for performing this techni'), [T1552.005 : Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005 'Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive dataMost cloud service providers support ')



---

`🔑 UUID : e7f05c4e-ca96-45e5-9788-116f802e1f32` **|** `🏷️ Version : 6` **|** `🗓️ Creation Date : 2022-11-30` **|** `🗓️ Last Modification : 2023-01-05` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : tvm::2.0`


## 👁️ Description

> Threat actors collect AWS IDs from EC instances by using AWS metadata
> service that is running by default. AWS account ID is a unique identifier
> that is used to identify an AWS account, AWS resource management or to
> access to AWS services.
> 
> Threat actors can extract different elements from metadata service, for
> example: 
> 
> - accountId
> - architecture
> - availabilityZone
> - billingProducts
> - devpayProductCodes
> - marketplaceProductCodes
> - imageId
> - instanceId
> - instanceType
> - kernelId
> - pendingTime
> - privateIp
> - ramdiskId
> - region
> - version
> 
> AWS metadata keeps information for the instance such as instance id,
> AMI id, hostname, ip address, security groups, public-ip and others.
> Instance metadata usually is divided into different categories. Instance
> metadata build based on the category is specified with a new version
> number. In some cases the instance metadata is available only when a new
> build version is launched. The categories are classified for example by
> elastic-gpu-id, role-name, instance-type, operation system (windows, mac or
> linux), ami-id (Amazon Machine Image ID), public-ip, vhostmd and by the
> version when category was released.
> 
> Examples: 
> 
> Category:                                        Version ID:
> ami-id                                           1.0
> block-device-mapping/ami                         2007-12-15
> elastic-gpus/associations/elastic-gpu-id         2016-11-30
> iam/security-credentials/role-name               2012-01-12
> network/interfaces/macs/mac/public-hostname      2011-01-01
> 
> Threat actors can extract information from the AWS metadata service with
> the user token and curl command. For curl commands - cURL tool is usually
> used for automation of AWS metadata information collection. 
> 
> Tools like curl on *nix-based systems, or Invoke-Rest Method in PowerShell
> on Windows are used for extraction of AWS metadata as they send GET requests
> for data collection. AWS exposes an Instance Metadata endpoint on every EC2 
> Instance at the address: http://169.254.169.254
> 
> Example: 
> 
> curl http://169.254.169.254/latest/meta-data/
> 
> OR
> 
> Curl command with a token for extraction of additional matadata information: 
> 
> TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
> curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document
> 
> Example for extraction of AWS metadata with bash script:
> 
> INSTANCEID=$(curl -sL http://169.254.169.254/latest/meta-data/instance-id)
> $ echo INSTANCEID
> 



## 🖥️ Terrain 

 > In AWS, the metadata service can by design be queried from a running
> instance. A threat actor needs to control an EC2 instance or a
> vulnerability in a running application that enables querying the instance
> meta data service remotely, such as a SSRF vulnerability.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🗃️ Collection`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques used to identify and gather data from a target network prior to exfiltration.

---

#### **🛰️ Domains**

 > Infrastructure technologies domain of interest to attackers.

 `☁️ Public Cloud` : Infrastructure handled by a commercial cloud provider. Managed mostly on a service level, and connected over the internet.

---

#### **🎯 Targets**

 > Granular delimited technical entities holding a value to the organization, that are targeted by adversaries. They might be also involved in the detection coverage as the target of log collection. Partially inspired by Veris.

  - [`🖥️ Web Application Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder
 - [`🖲️ Control Server`](https://collaborate.mitre.org/attackics/index.php/Control_Server) : A device which acts as both a server and controller, that hosts the control software used in communicating with lower-level control devices in an ICS network (e.g. Remote Terminal Units (RTUs) and Programmable Logic Controllers (PLCs)).
 - [`🖲️ Input/Output Server`](https://collaborate.mitre.org/attackics/index.php/Input/Output_Server) : The Input/Output (I/O) server provides the interface between the control system LAN applications and the field equipment monitored and controlled by the control system applications. The I/O server, sometimes referred to as a Front-End Processor (FEP) or Data Acquisition Server (DAS), converts the control system application data into packets that are transmitted over various types of communications media to the end device locations. The I/O server also converts data received from the various end devices over different communications mediums into data formatted to communicate with the control system networked applications.
 - [`🖥️ Public-Facing Servers`](http://veriscommunity.net/enums.html#section-asset) : Placeholder

---

#### **💿 Platforms concerned**

 > Actual technologies used by the organization that will be exploited by adversaries during a successful attack, and eventually of relevance for detection. Are named by commercial designation.

  - ` AWS` : Placeholder
 - [` AWS EC2`](https://docs.aws.amazon.com/ec2/index.html) : Amazon Elastic Compute Cloud (Amazon EC2) is a web service that provides resizable computing capacity—literally, servers in Amazon's data centers—that you use to build and host your software systems.

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

 [`😤 Nuisance`](http://veriscommunity.net/enums.html#section-impact) : Small and mostly inconsequential to day to day operations, but noticed.

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://hackingthe.cloud/aws/enumeration/account_id_from_ec2/
- [_2_] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- [_3_] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- [_4_] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
- [_5_] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- [_6_] https://medium.com/@radhagayathripatel/retrieving-aws-ec2-instance-metadata-using-metadata-in-scripts-251bf18dbabf

[1]: https://hackingthe.cloud/aws/enumeration/account_id_from_ec2/
[2]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
[3]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
[4]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
[5]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
[6]: https://medium.com/@radhagayathripatel/retrieving-aws-ec2-instance-metadata-using-metadata-in-scripts-251bf18dbabf

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


