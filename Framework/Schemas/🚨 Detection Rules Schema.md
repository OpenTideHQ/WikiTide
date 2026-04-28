# Detection Rules Schema 



> A Managed Detection Rule is ...

| Name                                | Field             | SubField         | SubSubField   | SubSubSubField   | Description                                                                                                                                                                                                                  | Type                | Example                                                        |
|:------------------------------------|:------------------|:-----------------|:--------------|:-----------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|:---------------------------------------------------------------|
| 🎫 Display name                      | `name`            |                  |               |                  | Verbose, human readable name for the detection rule                                                                                                                                                                          | string              | New Abnormal Credentials added to Azure AD                     |
| 🔗 References to information sources | `references`      |                  |               |                  | Schema for new references                                                                                                                                                                                                    | ['object', 'array'] |                                                                |
| 🕊️ Publicly available resources     |                   | `public`         |               |                  | Resources freely available on internet with no sharing constraints                                                                                                                                                           | object              |                                                                |
| 🏦 Private references                |                   | `internal`       |               |                  | Proprietary, sensible and confidential data belonging to the owner of the OpenTide instance where the object was modelled on, and which cannot be shared.                                                                    | object              |                                                                |
| 🗃️ Metadata                         | `metadata`        |                  |               |                  | Non technical indicators helping with overall data management                                                                                                                                                                | object              |                                                                |
| 🔑 UUID                              |                   | `uuid`           |               |                  | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                     | string              | 323d548d-17ca-46fa-a7c7-de43302456a1                           |
| 🧱 Schema Identifier                 |                   | `schema`         |               |                  | Identifier of the schema at its current version                                                                                                                                                                              | string              |                                                                |
| 🏷️ Version                          |                   | `version`        |               |                  | Latest revision of the model object, always in integer                                                                                                                                                                       | integer             | 3                                                              |
| 🗓️ Creation Date                    |                   | `created`        |               |                  | Creation date of initial version                                                                                                                                                                                             | string              | 2022-09-12                                                     |
| 🗓️ Last Modification                |                   | `modified`       |               |                  | Creation date of the latest version                                                                                                                                                                                          | string              | 2022-09-13                                                     |
| 🚦 Traffic Light Protocol 2.0        |                   | `tlp`            |               |                  | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time. | string              | green                                                          |
| 👩‍💻 Model author                    |                   | `author`         |               |                  | Creator of latest version                                                                                                                                                                                                    | string              | amine.besson@ext.ec.europa.eu                                  |
| 👥 Contributors                      |                   | `contributors`   |               |                  | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                        | array               |                                                                |
| Sharing Organisation                |                   | `organisation`   |               |                  | Details about the organisation who created and/or maintains the object                                                                                                                                                       | object              |                                                                |
| 🔑 Organisation UUID                 |                   |                  | `uuid`        |                  | UUID of the Sharing Organisation, version 4                                                                                                                                                                                  | string              |                                                                |
| 🎫 Organisation Name                 |                   |                  | `name`        |                  | Name of the Sharing Organisation                                                                                                                                                                                             | string              |                                                                |
| ✍ Metadata                          | `meta`            |                  |               |                  | Non technical indicators helping with overall data management                                                                                                                                                                | object              |                                                                |
| 🔑 UUID                              |                   | `uuid`           |               |                  | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                     | string              | 323d548d-17ca-46fa-a7c7-de43302456a1                           |
| 🧱 Schema Identifier                 |                   | `schema`         |               |                  | Identifier of the schema at its current version                                                                                                                                                                              | string              |                                                                |
| 🏷️ Version                          |                   | `version`        |               |                  | Latest revision of the model object, always in integer                                                                                                                                                                       | integer             | 3                                                              |
| 🗓️ Creation Date                    |                   | `created`        |               |                  | Creation date of initial version                                                                                                                                                                                             | string              | 2022-09-12                                                     |
| 🗓️ Last Modification                |                   | `modified`       |               |                  | Creation date of the latest version                                                                                                                                                                                          | string              | 2022-09-13                                                     |
| 🚦 Traffic Light Protocol 2.0        |                   | `tlp`            |               |                  | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time. | string              | green                                                          |
| 👩‍💻 Model author                    |                   | `author`         |               |                  | Creator of latest version                                                                                                                                                                                                    | string              | amine.besson@ext.ec.europa.eu                                  |
| 👥 Contributors                      |                   | `contributors`   |               |                  | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                        | array               |                                                                |
| Sharing Organisation                |                   | `organisation`   |               |                  | Details about the organisation who created and/or maintains the object                                                                                                                                                       | object              |                                                                |
| 🔑 Organisation UUID                 |                   |                  | `uuid`        |                  | UUID of the Sharing Organisation, version 4                                                                                                                                                                                  | string              |                                                                |
| 🎫 Organisation Name                 |                   |                  | `name`        |                  | Name of the Sharing Organisation                                                                                                                                                                                             | string              |                                                                |
| 🔬 Detection description             | `description`     |                  |               |                  | Explanation of what the detection rule is detecting, in order to give context to alerts receivers.                                                                                                                           | string              |                                                                |
| CoreTIDE Cyber Detection Model      | `detection_model` |                  |               |                  | CDM that this detection rule is implementing.                                                                                                                                                                                |                     | 0486fc80-bf0f-4bef-a3b2-471e2ce58b03 # Detect Execution of XYZ |
| Incident Response Details           | `response`        |                  |               |                  | Information regarding incident response procedures                                                                                                                                                                           | object              |                                                                |
| 🌡️ Alert Severity                   |                   | `alert_severity` |               |                  | Describes the level of attention required to handle the alert generated by the MDR.                                                                                                                                          | string              |                                                                |
| 👣 Playbook link                     |                   | `playbook`       |               |                  | Link an external playbook                                                                                                                                                                                                    | string              | https://internal-knowledge-base/playbook/account_brute_force   |
| ‍🚒 Alert Handling Team              |                   | `responders`     |               |                  | Team responsible for handling related incoming alerts                                                                                                                                                                        | string              |                                                                |
| Response Procedure                  |                   | `procedure`      |               |                  | Supportive information for the responders to alerts/events/incidents triggered by this detection rule                                                                                                                        | object              |                                                                |
| Alert Analysis                      |                   |                  | `analysis`    |                  | Guidelines to handle the alert                                                                                                                                                                                               | string              |                                                                |
| Supporting searches                 |                   |                  | `searches`    |                  | Data Queries that support the incident investigation process                                                                                                                                                                 | array               |                                                                |
| Short explanation of the search     |                   |                  |               | `purpose`        | Describes how the search supports the investigative process                                                                                                                                                                  | string              |                                                                |
| Target system for the search        |                   |                  |               | `system`         | On which system the query should run                                                                                                                                                                                         | string              |                                                                |
| 🔎 Supporting Search Query           |                   |                  |               | `query`          |                                                                                                                                                                                                                              | string              |                                                                |
| Incident Containment Guidelines     |                   |                  | `containment` |                  | Guidelines to contain the incident, once assessed to be a True Positive                                                                                                                                                      | string              |                                                                |
| 🛠️ Detection System Technical Setup | `configurations`  |                  |               |                  | Per system setup of the detection configurations                                                                                                                                                                             | object              |                                                                |

### Template

`MDR Detection Name.yaml`

```yaml
name: 
#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: 
  schema: mdr::2.1
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

description: |
  ...
#detection_model: 

response:
  alert_severity: 
  #playbook: https://
  #responders: 
  #procedure:
    #analysis: |
      #...
    #searches:
      #- purpose: |
          #...
        #system: 
        #query: |
          #...
    #containment: |
      #...

configurations:
  #sentinel: 
  #splunk: 
  #crowdstrike: 
  #carbon_black_cloud: 
  #defender_for_endpoint: 
  #sentinel_one:
```

