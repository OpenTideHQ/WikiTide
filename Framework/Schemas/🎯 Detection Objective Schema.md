# Detection Objective Schema 



> Detection Objectives represent a modelling of detection opportunities
against identified Threat Vectors


| Name                                   | Field        | SubField       | SubSubField   | SubSubSubField   | Description                                                                                                                                                                                                                                                                         | Type                | Example                              |
|:---------------------------------------|:-------------|:---------------|:--------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|:-------------------------------------|
| 🎫 Object Name                          | `name`       |                |               |                  | Name of the OpenTide Detection Objective                                                                                                                                                                                                                                            | string              |                                      |
| 🔗 References to information sources    | `references` |                |               |                  | Schema for new references                                                                                                                                                                                                                                                           | ['object', 'array'] |                                      |
| 🕊️ Publicly available resources        |              | `public`       |               |                  | Resources freely available on internet with no sharing constraints                                                                                                                                                                                                                  | object              |                                      |
| 🏦 Private references                   |              | `internal`     |               |                  | Proprietary, sensible and confidential data belonging to the owner of the OpenTide instance where the object was modelled on, and which cannot be shared.                                                                                                                           | object              |                                      |
| 🗃️ Metadata                            | `metadata`   |                |               |                  | Non technical indicators helping with overall data management                                                                                                                                                                                                                       | object              |                                      |
| 🔑 UUID                                 |              | `uuid`         |               |                  | According to UUIDv4 specification. You can use https://www.uuidgenerator.net/version4 to generate UUIDs.                                                                                                                                                                            | string              | 323d548d-17ca-46fa-a7c7-de43302456a1 |
| 🧱 Schema Identifier                    |              | `schema`       |               |                  | Identifier of the schema at its current version                                                                                                                                                                                                                                     | string              |                                      |
| 🏷️ Version                             |              | `version`      |               |                  | Latest revision of the model object, always in integer                                                                                                                                                                                                                              | integer             | 3                                    |
| 🗓️ Creation Date                       |              | `created`      |               |                  | Creation date of initial version                                                                                                                                                                                                                                                    | string              | 2022-09-12                           |
| 🗓️ Last Modification                   |              | `modified`     |               |                  | Creation date of the latest version                                                                                                                                                                                                                                                 | string              | 2022-09-13                           |
| 🚦 Traffic Light Protocol 2.0           |              | `tlp`          |               |                  | The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time.                                                        | string              | green                                |
| 👩‍💻 Model author                       |              | `author`       |               |                  | Creator of latest version                                                                                                                                                                                                                                                           | string              | amine.besson@ext.ec.europa.eu        |
| 👥 Contributors                         |              | `contributors` |               |                  | Individuals who supported creating, enriching or informing the information contained in the document.                                                                                                                                                                               | array               |                                      |
| Sharing Organisation                   |              | `organisation` |               |                  | Details about the organisation who created and/or maintains the object                                                                                                                                                                                                              | object              |                                      |
| 🔑 Organisation UUID                    |              |                | `uuid`        |                  | UUID of the Sharing Organisation, version 4                                                                                                                                                                                                                                         | string              |                                      |
| 🎫 Organisation Name                    |              |                | `name`        |                  | Name of the Sharing Organisation                                                                                                                                                                                                                                                    | string              |                                      |
| Detection Objective                    | `objective`  |                |               |                  | Describes a detection concept, alongside technical descriptions for precise detection opportunities called signals.                                                                                                                                                                 | object              |                                      |
| ❗ Priority                             |              | `priority`     |               |                  | How important the detection objective is to implement                                                                                                                                                                                                                               | string              |                                      |
| 🗡️ MITRE ATT&CK Technique Mapping      |              | `att&ck`       |               |                  | Optional, allows a more precise mapping of the ATT&CK techniques associated with the detection objectives. If not precised, the ATT&CK Techniques mapped by the related Threat Vectors must be considered instead.                                                                  | array               |                                      |
| Detection Objective Type               |              | `type`         |               |                  | Purpose of the Detection Objective                                                                                                                                                                                                                                                  | string              |                                      |
| Threat Vectors Coverage                |              | `threats`      |               |                  | OpenTide Threat Vectors which are covered by this Detection Objective. Required when the objective type is "Threat", forbidden otherwise.                                                                                                                                           | array               |                                      |
| Expected investment into the objective |              | `investment`   |               |                  | How much overall investment is expected in developing the detection objective capabilities. This may take in account larger problematics than the effort to implement signals using the `effort` keyword, for example when new log sources, tooling, or infrastructure is required. | string              |                                      |
| 🔬 Objective Description                |              | `description`  |               |                  | High Level description of the Detection Objective goal and key concept. Technical description of different detection methodologies/signals must be done under signals.                                                                                                              | string              |                                      |
| Signal Composition                     |              | `composition`  |               |                  | Models how the signals described should be used as part of a final detection implementation                                                                                                                                                                                         | object              |                                      |
| Signal Correlation Strategy            |              |                | `strategy`    |                  | Describes how signals should be used - from fully synergetic, to fully separate                                                                                                                                                                                                     | string              |                                      |
| 🔬 Correlation Strategy                 |              |                | `description` |                  | Technical details about the recommended strategy                                                                                                                                                                                                                                    | string              |                                      |
| Detection Signals                      |              | `signals`      |               |                  | Detailed, technical description of each detection opportunies, aligned with the overarching Detection Objectives. These signals can all be independent opportunities, or related within a larger higher-order detection strategy which can be documented under correlation.         | array               |                                      |
| 🎫 Signal Name                          |              |                | `name`        |                  | Name of the Detection Signal - in general, this should be a good name for an alert.                                                                                                                                                                                                 | string              |                                      |
| 🔑 Signal UUID                          |              |                | `uuid`        |                  | A UUIDv4 to uniquely identify the Detection Signal.                                                                                                                                                                                                                                 | string              |                                      |
| 🔬 Signal Description                   |              |                | `description` |                  | Detailed, low level technical details allowing to transform this specification into Detection Rules.                                                                                                                                                                                | string              |                                      |
| 💣 Signal Severity                      |              |                | `severity`    |                  | How critical this signal should be processed. In general, this should map closely to the alert severity that the detection rule would raise.                                                                                                                                        | string              |                                      |
| Signal Implement Effort                |              |                | `effort`      |                  | Rough estimate of the technical effort required. This is usually environment dependent based.  From 1 to 10, 1 being a very quick action, 10 taking resources across several cycles.                                                                                                | number              |                                      |
| Detection Methodology                  |              |                | `methodology` |                  | High level category of the type of detection approach that the signal specification is proposing.                                                                                                                                                                                   | string              |                                      |
| Required Data                          |              |                | `data`        |                  | Modelling of the required data to implement the signal                                                                                                                                                                                                                              | object              |                                      |
| Data Availability                      |              |                |               | `availability`   | Represents whether the necessary data is already captured                                                                                                                                                                                                                           | string              |                                      |
| Data Requirements                      |              |                |               | `requirements`   | Technical details of the required data                                                                                                                                                                                                                                              | string              |                                      |
| 📑 Possible Logsources                  |              |                |               | `logsources`     | Existing, available logsources which cover the data requirements for the signal                                                                                                                                                                                                     | array               |                                      |
| Entities                               |              |                | `entities`    |                  | Entities that the signal is using to perform its detection. Particularly useful to know for alert processing, entity grouping etc.                                                                                                                                                  | array               |                                      |
| External Detectors                     |              |                | `detectors`   |                  | Detection existing in some toolings/platforms, but which does not exist as an OpenTide Detection Rule, stored as-code. Useful to represent detectors, vendor detections, and black-box capabilities documented by vendors but not necessarily fully controlled.                     | array               |                                      |
| 🎫 Detector Name                        |              |                |               | `name`           | Name of the external detector, either as documented by the vendor if available, else close to the alerts generated by the tool.                                                                                                                                                     | string              |                                      |
| Detector Technology                    |              |                |               | `technology`     | The technology/platform that provides this detection capability. Select from available detectors configured in visibility.toml                                                                                                                                                      | string              |                                      |
| 🔬 Detector Description                 |              |                |               | `description`    | High level overview over the external detection capabilities                                                                                                                                                                                                                        | string              |                                      |
| 🔗 Detector Reference                   |              |                |               | `link`           | Link to relevant docs, if available, for the external detection                                                                                                                                                                                                                     | string              |                                      |
| Detection Examples                     |              |                | `examples`    |                  | When available, relevant queries/detection rules already shared in open-source repositories or vendor detection libraries                                                                                                                                                           | array               |                                      |
| 🔬 Detection Example Description        |              |                |               | `description`    | High level overview of the detection example and its approach                                                                                                                                                                                                                       | string              |                                      |
| 🔗 Community Detection Link             |              |                |               | `link`           | Link to the shared detection (github, blog post, vendor repository...)                                                                                                                                                                                                              | string              |                                      |
| Query Language                         |              |                |               | `language`       | When relevant, the language of the shared detection query                                                                                                                                                                                                                           | string              |                                      |
| 🔎 Detection Query                      |              |                |               | `query`          | When relevant, the detection query that was shared                                                                                                                                                                                                                                  | string              |                                      |

### Template

`Object Name.yaml`

```yaml
name: 

#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: 
  schema: dom::1.0
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

objective:
  priority: 
  #att&ck:
    #-
  type: Threat
  #threats:
    #-
  #investment: 
  description: |
    ...

  composition:
    strategy: 
    description: |
      ...
  signals:
    - name: 
      uuid: 
      description: |
        ...
      severity: 
      #effort: 
      methodology: 
      data:
        availability: 
        requirements: |
          ...
        #logsources:
          #-
      entities:
        - 
      #detectors:
        #- name: 
          #technology: 
          #description: |
            #...
          #link: 
      #examples:
        #- description: |
            #...
          #link: 
          #language: 
          #query: |
            #...
```

