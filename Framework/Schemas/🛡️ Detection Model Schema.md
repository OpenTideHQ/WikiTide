# Detection Model Schema 



> CoreTIDE Data Model Specification for Cyber Detection Models

| Name                                      | Field         | SubField       | SubSubField   | Description                                                                                                                                                                                                                  | Type                | Example                                                                                                                        |
|:------------------------------------------|:--------------|:---------------|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|:-------------------------------------------------------------------------------------------------------------------------------|
| 🎫 Model Name                              | `name`        |                |               | Name of the detection model                                                                                                                                                                                                  | string              | Placeholder                                                                                                                    |
| 🔥 Vector criticality                      | `criticality` |                |               | Priority to implement to achieve detection objectives                                                                                                                                                                        | string              | Emergency                                                                                                                      |
| 🔗 References to information sources       | `references`  |                |               | Schema for new references                                                                                                                                                                                                    | ['object', 'array'] |                                                                                                                                |
| 🕊️ Publicly available resources           |               | `public`       |               | Resources freely available on internet with no sharing constraints                                                                                                                                                           | object              |                                                                                                                                |
| 🏦 Private references                      |               | `internal`     |               | Proprietary, sensible and confidential data belonging to the owner of the OpenTide instance where the object was modelled on, and which cannot be shared.                                                                    | object              |                                                                                                                                |
| 🗃️ Metadata                               | `metadata`    |                |               | Non technical indicators helping with overall data management                                                                                                                                                                | object              |                                                                                                                                |
| 🔑 UUID                                    |               | `uuid`         |               | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                     | string              | 323d548d-17ca-46fa-a7c7-de43302456a1                                                                                           |
| 🧱 Schema Identifier                       |               | `schema`       |               | Identifier of the schema at its current version                                                                                                                                                                              | string              |                                                                                                                                |
| 🏷️ Version                                |               | `version`      |               | Latest revision of the model object, always in integer                                                                                                                                                                       | integer             | 3                                                                                                                              |
| 🗓️ Creation Date                          |               | `created`      |               | Creation date of initial version                                                                                                                                                                                             | string              | 2022-09-12                                                                                                                     |
| 🗓️ Last Modification                      |               | `modified`     |               | Creation date of the latest version                                                                                                                                                                                          | string              | 2022-09-13                                                                                                                     |
| 🚦 Traffic Light Protocol 2.0              |               | `tlp`          |               | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time. | string              | green                                                                                                                          |
| 👩‍💻 Model author                          |               | `author`       |               | Creator of latest version                                                                                                                                                                                                    | string              | amine.besson@ext.ec.europa.eu                                                                                                  |
| 👥 Contributors                            |               | `contributors` |               | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                        | array               |                                                                                                                                |
| Sharing Organisation                      |               | `organisation` |               | Details about the organisation who created and/or maintains the object                                                                                                                                                       | object              |                                                                                                                                |
| 🔑 Organisation UUID                       |               |                | `uuid`        | UUID of the Sharing Organisation, version 4                                                                                                                                                                                  | string              |                                                                                                                                |
| 🎫 Organisation Name                       |               |                | `name`        | Name of the Sharing Organisation                                                                                                                                                                                             | string              |                                                                                                                                |
| 🛡️ Description of the detection objective | `detection`   |                |               | Set of data detailing how and where to perform the detection, following an analysis and research process                                                                                                                     | object              |                                                                                                                                |
| Threat Vector Model                       |               | `vectors`      |               | Threat Vectors that need to be detected                                                                                                                                                                                      | array               | TVM0001                                                                                                                        |
| ⛓️ Cyber Kill Chain                       |               | `killchain`    |               | Where the vector is positionned in the kill chain of adversarial operations                                                                                                                                                  | ['string', 'array'] | Lateral Movement                                                                                                               |
| 🗡️ ATT&CK Technique                       |               | `att&ck`       |               | Optional, when the detection model is specific of a particular att&ck technique. Else, techniques will be looked up from the TVMs.                                                                                           | string              | T1606                                                                                                                          |
| ⚔️ Technical Detection Methods            |               | `methods`      |               | MITRE D3FEND Detect Techniques that describe the approach required by the detection model to fulfill its objectives best during implementation.                                                                              | array               | Resource Access Pattern Analysis                                                                                               |
| 💪 Detection Maturity Level                |               | `maturity`     |               | The Detection Maturity Level (DML) model is a capability maturity model for referencing the required CDM maturity to achieve its cyber attack detection goals.                                                               | string              | Tools                                                                                                                          |
| 🤔 Difficulty to implement                 |               | `feasibility`  |               | Estimated hardship that will be encountered to implement model, from data required and method                                                                                                                                | string              | Straightforward                                                                                                                |
| 🗡️ ATT&CK Data Sources                    |               | `datasources`  |               | ATT&CK Data source reference                                                                                                                                                                                                 | array               | Process                                                                                                                        |
| 📢 Possible data collection points         |               | `collection`   |               | If available, suggested data logs options for the detection model implementation                                                                                                                                             | array               | Cloudwatch                                                                                                                     |
| 🏺 D3FEND Digital Artifacts                |               | `artifacts`    |               | Digital Artifacts are in D3FEND an ontology of objects useful for cyberdefense engineering and which allow to get a real-world anchor to the model.                                                                          | array               | Domain Name                                                                                                                    |
| 🧪 Guidelines                              |               | `guidelines`   |               | Detailed technical explanation of the detection objective, and goals to implement it , in short sentences                                                                                                                    | string              | Lookup file modification logs, and chart statistics of access across 5 min intervals                                           |
| 🔧 Tuning                                  |               | `tuning`       |               | Recommendations to tune out false positives without damaging the alert                                                                                                                                                       | string              | Some development workstations may be prone to false positive, but be mindful that production servers should not be whitelisted |

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
  schema: cdm::2.0
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

detection:
  vectors:
    - 
  #killchain: 
  #att&ck: 
  methods:
    - 
  maturity: 
  feasibility: 
  datasources:
    - 
  collection:
    - 
  artifacts:
    - 
  guidelines: |
    ...
  tuning: |
    ...
```

