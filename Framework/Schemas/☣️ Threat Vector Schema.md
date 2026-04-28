# Threat Vector Schema 



> CoreTIDE Data Model Specification for  Threat Vector Models

| Name                                  | Field         | SubField       | SubSubField   | Description                                                                                                                                                                                                                  | Type                | Example                                                                |
|:--------------------------------------|:--------------|:---------------|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|:-----------------------------------------------------------------------|
| 🎫 Model Name                          | `name`        |                |               | Name of the detection model                                                                                                                                                                                                  | string              | Placeholder                                                            |
| 🔥 Vector criticality                  | `criticality` |                |               | Objective calculation from severity, impact and sophistication                                                                                                                                                               | string              | Emergency                                                              |
| 🔗 References to information sources   | `references`  |                |               | Schema for new references                                                                                                                                                                                                    | ['object', 'array'] |                                                                        |
| 🕊️ Publicly available resources       |               | `public`       |               | Resources freely available on internet with no sharing constraints                                                                                                                                                           | object              |                                                                        |
| 🏦 Private references                  |               | `internal`     |               | Proprietary, sensible and confidential data belonging to the owner of the OpenTide instance where the object was modelled on, and which cannot be shared.                                                                    | object              |                                                                        |
| 🗃️ Metadata                           | `metadata`    |                |               | Non technical indicators helping with overall data management                                                                                                                                                                | object              |                                                                        |
| 🔑 UUID                                |               | `uuid`         |               | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                     | string              | 323d548d-17ca-46fa-a7c7-de43302456a1                                   |
| 🧱 Schema Identifier                   |               | `schema`       |               | Identifier of the schema at its current version                                                                                                                                                                              | string              |                                                                        |
| 🏷️ Version                            |               | `version`      |               | Latest revision of the model object, always in integer                                                                                                                                                                       | integer             | 3                                                                      |
| 🗓️ Creation Date                      |               | `created`      |               | Creation date of initial version                                                                                                                                                                                             | string              | 2022-09-12                                                             |
| 🗓️ Last Modification                  |               | `modified`     |               | Creation date of the latest version                                                                                                                                                                                          | string              | 2022-09-13                                                             |
| 🚦 Traffic Light Protocol 2.0          |               | `tlp`          |               | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time. | string              | green                                                                  |
| 👩‍💻 Model author                      |               | `author`       |               | Creator of latest version                                                                                                                                                                                                    | string              | amine.besson@ext.ec.europa.eu                                          |
| 👥 Contributors                        |               | `contributors` |               | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                        | array               |                                                                        |
| Sharing Organisation                  |               | `organisation` |               | Details about the organisation who created and/or maintains the object                                                                                                                                                       | object              |                                                                        |
| 🔑 Organisation UUID                   |               |                | `uuid`        | UUID of the Sharing Organisation, version 4                                                                                                                                                                                  | string              |                                                                        |
| 🎫 Organisation Name                   |               |                | `name`        | Name of the Sharing Organisation                                                                                                                                                                                             | string              |                                                                        |
| ☣️ Threat                             | `threat`      |                |               | Technical details regarding the threat vector                                                                                                                                                                                | object              |                                                                        |
| 🐲 Threat Actors                       |               | `actors`       |               | Attributes related threat activities with a known activity cluster                                                                                                                                                           | array               |                                                                        |
| 🐲 Threat Actor                        |               |                | `name`        | TBD                                                                                                                                                                                                                          | string              |                                                                        |
| Threat Actor Sightings                |               |                | `sighting`    |                                                                                                                                                                                                                              | string              |                                                                        |
| 🔗 Sightings References                |               |                | `references`  |                                                                                                                                                                                                                              | array               |                                                                        |
| ⛓️ Cyber Kill Chain                   |               | `killchain`    |               | Where the vector is positionned in the kill chain of adversarial operations                                                                                                                                                  | ['string', 'array'] | Lateral Movement                                                       |
| 🗡️ ATT&CK Techniques                  |               | `att&ck`       |               | T-ID of the techniques related to the Vector                                                                                                                                                                                 | array               | T1098                                                                  |
| ⛓️ Vector Chaining                    |               | `chaining`     |               | Describe the relation of this threat vector to others                                                                                                                                                                        | array               |                                                                        |
| 🔗 Vectors Relationship                |               |                | `relation`    |                                                                                                                                                                                                                              | string              |                                                                        |
| ☣️ Target Threat Vector Model         |               |                | `vector`      | The target of the relationship the chain is representing                                                                                                                                                                     | string              |                                                                        |
| ✏️ Chaining Description               |               |                | `description` | Describe with sufficient details the relation between                                                                                                                                                                        | string              |                                                                        |
| ❤️‍🩹 Common Vulnerability Enumeration |               | `cve`          |               | CVEs related to the TVM                                                                                                                                                                                                      | array               | CVE-2020-7491                                                          |
| 🌌 Related MISP Events                 |               | `misp`         |               | List of MISP event UUID(s) that are related to this threat vector                                                                                                                                                            | array               | 74c11cb4-b903-4541-aaa2-1db925902fb9                                   |
| 🌐 Threat Surface                      |               | `surface`      |               | Hierarchical scoping of technologies and environments applicable to the threat vector, using category::target notation                                                                                                       | array               | OS::Windows                                                            |
| 🛰️ Domains [DEPRECATED]               |               | `domains`      |               | [DEPRECATED - use surface] High-level technology domain concerned by the model                                                                                                                                               | array               | Public Cloud                                                           |
| 🖥️ Technical terrain                  |               | `terrain`      |               | Precisions on what combination of software, infrastructure or configurations need to present before the threat is realized.                                                                                                  | string              | Adversary must have administrative priviledges over domain controller. |
| 🎯 Targets [DEPRECATED]                |               | `targets`      |               | [DEPRECATED - use surface] Category of devices or services where the attack is executed on, or upon                                                                                                                          | array               | Microservices                                                          |
| 💿 Platforms concerned [DEPRECATED]    |               | `platforms`    |               | [DEPRECATED - use surface] Technical platforms that may be concerned by the vector                                                                                                                                           | array               | Kubernetes                                                             |
| 💣 Severity                            |               | `severity`     |               | Name of the technical environment the threat is known to have been executed on or upon.                                                                                                                                      | string              | AWS                                                                    |
| 🪄 Leverage acquisition                |               | `leverage`     |               | Adversarial acquisition of capabilities over the target system.                                                                                                                                                              | array               | Spoofing                                                               |
| 💥 Impact                              |               | `impact`       |               | Technical consequences of the vector                                                                                                                                                                                         | array               | IP Loss                                                                |
| 🎲 Vector Viability                    |               | `viability`    |               | Likelyhood of the vector to be successfully exploited                                                                                                                                                                        | string              | Unproven                                                               |
| 🔬 Description of the threat           |               | `description`  |               | Explanation of the threat, and how it is exercised in adversaries operations                                                                                                                                                 | string              | Placeholder                                                            |

### Template

`Object Name.yaml`

```yaml
name: 
criticality: 
#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: 
  schema: tvm::2.1
  version: 
  created: YYYY-MM-DD
  modified: YYYY-MM-DD
  tlp: 
  #author: 
  #contributors:
    #-
  #organisation:
    #uuid: 
    #name: 

threat:
  #actors:
    #- name: 
      #sighting: |
        #...
      #references:
        #-
  #killchain: 
  att&ck:
    - 
  #chaining:
    #- relation: 
      #vector: 
      #description: |
        #...
  #cve:
    #-
  #misp:
    #-
  #surface:
    #-
  terrain: |
    ...
  severity: 
  leverage:
    - 
  impact:
    - 
  viability: 
  description: |
    ...
```

