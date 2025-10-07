#   



> 

| Name                           | Field          | SubField      | Description                                                                                                                                                                                                                                                                                                                                         | Type   | Example   |
|:-------------------------------|:---------------|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------|:----------|
| Schema identifier and version  | `schema`       |               | Identifier of the schema at its current version                                                                                                                                                                                                                                                                                                     | string |           |
| ♻️ Status of the use-case      | `status`       |               | Define the status according to use case development life cycle process                                                                                                                                                                                                                                                                              | string | STAGING   |
| 👥 Development Contributors     | `contributors` |               | Individuals who supported creating, enriching or tuning the detection.                                                                                                                                                                                                                                                                              | array  |           |
| 🏢 Target Tenants               | `tenants`      |               | Override the default organizations and deploy to selected tenants only.                                                                                                                                                                                                                                                                             | array  |           |
| 🚩 Flags                        | `flags`        |               | Flags allow to customize the rule behaviour using the modifiers framework                                                                                                                                                                                                                                                                           | array  |           |
| Correlation Rules Details      | `details`      |               | Some of those parameters are optional, and generic MDR details will be used in place                                                                                                                                                                                                                                                                | object |           |
| 🎫 The name of the rule.        |                | `name`        |                                                                                                                                                                                                                                                                                                                                                     | string |           |
| 🔬 The description of the rule. |                | `description` |                                                                                                                                                                                                                                                                                                                                                     | string |           |
| 💣 Rule Severity                |                | `severity`    |                                                                                                                                                                                                                                                                                                                                                     | string |           |
| Trigger Type                   |                | `trigger`     | - Verbose: One outcome generated for each result matching the query   Total outcomes are limited per rule trigger.  - Summary: One outcome generated for all results matching the query   Total results included in the outcome are limited per rule trigger.                                                                                       | string |           |
| Rule Outcome                   |                | `outcome`     | Whether to create a detection or incident if a match is found                                                                                                                                                                                                                                                                                       | string |           |
| MITRE ATT&CK Tactic            |                | `tactic`      | The relevant MITRE ATT&CK Tactic mapping to this detection                                                                                                                                                                                                                                                                                          | string |           |
| MITRE ATT&CK Technique         |                | `technique`   | Relevant MITRE ATT&CK Technique to map. You may only use it if tactic is first filled in. Important - double check on the GUI which Techniques are available first, then lookup their ID. Crowdstrike only supports a subset of the latest ATT&CK definition.                                                                                       | string |           |
| Correlation Rule Schedule      | `schedule`     |               |                                                                                                                                                                                                                                                                                                                                                     | object |           |
| Schedule Start                 |                | `start`       | The UTC time to start running the query. For example: 2024-11-19T19:00:00Z If no value is specified, this defaults to 15 minutes from the current time.                                                                                                                                                                                             | string |           |
| Schedule End                   |                | `end`         | The UTC time to stop running the query. For example: 2024-11-19T19:00:00Z If no value is specified, no stop time is used.                                                                                                                                                                                                                           | string |           |
| ⏱ Schedule Frequency           |                | `frequency`   | How often to run the query. The format is as follow: NdNhNm, where d, h and m can be combined, for example 1m, 5h10m, 1d2h etc. A minimal of 5m is required.                                                                                                                                                                                        | string |           |
| ⌛ Schedule Lookback/Window     |                | `lookback`    | To ensure that all relevant data is searched, configure the lookback to be at least as long as the search frequency. Overlapping searches help to ensure that all relevant data is included, regardless of when logs are uploaded. However, with overlapping searches, a given event or indicator might appear in more than one resulting incident. | string |           |
| 🔎 Search Query                 | `query`        |               |                                                                                                                                                                                                                                                                                                                                                     | string |           |

### Template

``

```yaml
  
  details:
    #name: 
    #description: |
      #...
    #severity: 
    trigger: 
    outcome: 
    #tactic: 
    #technique: 
  
  schedule:
    #start: 
    #end: 
    frequency: 
    lookback: 
  
  query: |
    ...
```

