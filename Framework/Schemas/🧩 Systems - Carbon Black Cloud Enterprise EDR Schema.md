#   



> 

| Name                                | Field           | Description                                                                                                                                              | Type    | Example                                      |
|:------------------------------------|:----------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|:--------|:---------------------------------------------|
| Schema identifier and version       | `schema`        | Identifier of the schema at its current version                                                                                                          | string  |                                              |
| ♻️ Status of the use-case           | `status`        | Define the status according to use case development life cycle process                                                                                   | string  | STAGING                                      |
| 👥 Development Contributors          | `contributors`  | Individuals who supported creating, enriching or tuning the detection.                                                                                   | array   |                                              |
| 🏢 Organizations                     | `organizations` | Override the default organizations the deployment will configure the reports onto.                                                                       | array   |                                              |
| 🔎 Watchlist                         | `watchlist`     | Override the default watchlist the report is added to.                                                                                                   | string  | Advanced_Threats                             |
| ⚠️ Threat Report                    | `report`        | Default logic is to add the MDR to a report automatically generated from the same name. It is also possible to deploy to a report with a different name. | string  | Sudo Escalation Techniques                   |
| 🏷️ Custom tags                      | `tags`          | Carbon black query IOC                                                                                                                                   | array   |                                              |
| 💣 Custom Severity Score             | `severity`      | Allows to override the default severity mapping from the MDR with a custom value.                                                                        | integer |                                              |
| 🔎 Carbon Black Cloud Detection Rule | `query`         | Carbon black query IOC                                                                                                                                   | string  | process_md5:6d7c8a951af6ad6835c029b3cb88d333 |

### Template

``

```yaml
  schema: carbon_black_cloud::2.0
  status: DEVELOPMENT
  #contributors:
    #-
  #report: 
  #tags:
    #-
  query: |
    ...
```

