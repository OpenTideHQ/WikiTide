# Business Detection Schema 



> Business Driven Detection are non-threat related detection objectives, which are defined as a consequence of compliance, policies or other regulations.

| Name                                      | Field         | SubField         | SubSubField   | Description                                                                                                                                                                                                                  | Type                | Example                                                         |
|:------------------------------------------|:--------------|:-----------------|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|:----------------------------------------------------------------|
| 🎫 Model Name                              | `name`        |                  |               | Name of the detection objective                                                                                                                                                                                              | string              | Monitor non-partner IP logons                                   |
| 🔥 Detection criticality                   | `criticality` |                  |               | Describes how the implementation should be prioritized                                                                                                                                                                       | string              | Emergency                                                       |
| 🔗 References to information sources       | `references`  |                  |               | Schema for new references                                                                                                                                                                                                    | ['object', 'array'] |                                                                 |
| 🕊️ Publicly available resources           |               | `public`         |               | Resources freely available on internet with no sharing constraints                                                                                                                                                           | object              |                                                                 |
| 🏦 Private references                      |               | `internal`       |               | Proprietary, sensible and confidential data belonging to the owner of the OpenTide instance where the object was modelled on, and which cannot be shared.                                                                    | object              |                                                                 |
| 🗃️ Metadata                               | `metadata`    |                  |               | Non technical indicators helping with overall data management                                                                                                                                                                | object              |                                                                 |
| 🔑 UUID                                    |               | `uuid`           |               | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                     | string              | 323d548d-17ca-46fa-a7c7-de43302456a1                            |
| 🧱 Schema Identifier                       |               | `schema`         |               | Identifier of the schema at its current version                                                                                                                                                                              | string              |                                                                 |
| 🏷️ Version                                |               | `version`        |               | Latest revision of the model object, always in integer                                                                                                                                                                       | integer             | 3                                                               |
| 🗓️ Creation Date                          |               | `created`        |               | Creation date of initial version                                                                                                                                                                                             | string              | 2022-09-12                                                      |
| 🗓️ Last Modification                      |               | `modified`       |               | Creation date of the latest version                                                                                                                                                                                          | string              | 2022-09-13                                                      |
| 🚦 Traffic Light Protocol 2.0              |               | `tlp`            |               | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time. | string              | green                                                           |
| 💡 Data Classification                     |               | `classification` |               | Data Classification Marking                                                                                                                                                                                                  | string              | SECRET UE/EU SECRET                                             |
| 👩‍💻 Model author                          |               | `author`         |               | Creator of latest version                                                                                                                                                                                                    | string              | amine.besson@ext.ec.europa.eu                                   |
| 👥 Contributors                            |               | `contributors`   |               | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                        | array               |                                                                 |
| Sharing Organisation                      |               | `organisation`   |               | Details about the organisation who created and/or maintains the object                                                                                                                                                       | object              |                                                                 |
| 🔑 Organisation UUID                       |               |                  | `uuid`        | UUID of the Sharing Organisation, version 4                                                                                                                                                                                  | string              |                                                                 |
| 🎫 Organisation Name                       |               |                  | `name`        | Name of the Sharing Organisation                                                                                                                                                                                             | string              |                                                                 |
| 🏛️ Description of the detection objective | `request`     |                  |               | Set of data detailing how and where to perform the detection, following an analysis and research process                                                                                                                     | object              |                                                                 |
| 🛰️ Domains                                |               | `domains`        |               | High-level technology domain concerned by the model                                                                                                                                                                          | array               | Public Cloud                                                    |
| 🎯 Targets                                 |               | `targets`        |               | Category of devices or services where the attack is executed on, or upon                                                                                                                                                     | array               | Microservices                                                   |
| 💿 Platforms concerned                     |               | `platforms`      |               | Technical platforms that may be concerned by the vector                                                                                                                                                                      | array               | Kubernetes                                                      |
| 👮 Policy, mandate or governance violation |               | `violation`      |               | Category of the policy violation this request is addressing                                                                                                                                                                  | string              | Illegal or aberrant application found on host                   |
| Reason of the request                     |               | `justification`  |               | Explanation of why the request was dispatched                                                                                                                                                                                | string              | Need to flag out of date web browser to reach updating policies |
| 🔬 Description of the request              |               | `description`    |               | Explanation of the request, and how it should be implemented in operations                                                                                                                                                   | string              | Monitor for outdated user agents in web requests                |

### Template

`BDR0001 - Object Name.yaml`

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
  schema: bdr::2.0
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

request:
  domains:
    - 
  #targets:
    #-
  #platforms:
    #-
  violation: 
  justification: |
    ...
  description: |
    ...
```

