#   



> 

| Name                               | Field             | SubField          | SubSubField   | Description                                                                                                                                                                                                                                    | Type    | Example                                                          |
|:-----------------------------------|:------------------|:------------------|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------|:-----------------------------------------------------------------|
| Schema identifier and version      | `schema`          |                   |               | Identifier of the schema at its current version                                                                                                                                                                                                | string  |                                                                  |
| Status of the use-case             | `status`          |                   |               | Define the status according to use case development life cycle process                                                                                                                                                                         | string  |                                                                  |
| 👥 Development Contributors         | `contributors`    |                   |               | Individuals who supported creating, enriching or tuning the detection.                                                                                                                                                                         | array   |                                                                  |
| ⚖️ Event threshold                 | `threshold`       |                   |               | If amount of events is higher than threshold (during the timeframe) the alert is triggered. Default = 0.                                                                                                                                       | integer | 10                                                               |
| 🗜️ Throttling parameters           | `throttling`      |                   |               | Configuration for throttling incoming alerts                                                                                                                                                                                                   | object  |                                                                  |
| 🔖 Throttling Fields                |                   | `fields`          |               | Fields to check for matching values in events. Events with the same value for these fields are suppressed.                                                                                                                                     | array   | dst                                                              |
| ⌛ Throttling Period                |                   | `duration`        |               | How long do discard new alerts that have the same characteristics (duplicate alerts), based on the fields defined below in hours/days. Default same as scheduling (value = 1h).                                                                | string  | 5m                                                               |
| ⏲ Throttling parameters            | `scheduling`      |                   |               | Configuration for throttling incoming alerts                                                                                                                                                                                                   | object  |                                                                  |
| ⏲ Scheduled search cron scheduling |                   | `cron`            |               | Cron Expression describing the scheduling for running the search.                                                                                                                                                                              | string  | 0 4 8-14 * *                                                     |
| ⏱ Recurring Search Interval        |                   | `frequency`       |               | Time intervals at which the scheduled search should be ran at. Warning: due to implementation details, only the following intervals are allowed for Splunk : 1-59m , 1-23h , 1-30d . For more complex scheduling, use the cron option instead. | string  | 5m                                                               |
| Custom Frequency Setup             |                   | `custom_time`     |               | Customize the base time that the frequency takes as an anchor. Expects HHhmm format. See frequency description for more explanation in how they interact.                                                                                      | string  | 12:30                                                            |
| ⌛ Lookback Configuration           |                   | `lookback`        |               | Duration of logs to search in                                                                                                                                                                                                                  | string  | 5m                                                               |
| 🎖️ Notable Event Settings          | `notable`         |                   |               | Configuration for notable events generated by the alert                                                                                                                                                                                        | object  |                                                                  |
| 📣 Notable Event Configuration      |                   | `event`           |               | Describes attributes related to the notable event                                                                                                                                                                                              | object  |                                                                  |
| 🪪 Notable Event Name               |                   |                   | `title`       | Supporting $token usage                                                                                                                                                                                                                        | string  | New Abnormal Credentials added to Azure AD from user $logonuser  |
| 🔬 Notable Event Description        |                   |                   | `description` | Supporting $token usage                                                                                                                                                                                                                        | string  | <insert example>                                                 |
| 🕵 Drilldown search configuration   |                   | `drilldown`       |               | Describes attributes related to drilldown search accompanying the notable event.                                                                                                                                                               | object  |                                                                  |
| 🎫 Drilldown Search Name            |                   |                   | `name`        | Name of the secondary search                                                                                                                                                                                                                   | string  |                                                                  |
| ❓ Drilldown Search                 |                   |                   | `search`      | A custom secondary search.                                                                                                                                                                                                                     | string  |                                                                  |
| 🛡️ Security Domain                 |                   | `security_domain` |               | Categorization of the notable event                                                                                                                                                                                                            | string  | Threat                                                           |
| 🛡️ Security Domain                 | `security_domain` |                   |               | This keyword is deprecated and only kept for compatibility reasons. You are expected to use security_domain nested under notable.                                                                                                              | string  | Threat                                                           |
| Splunk Risk Analysis               | `risk`            |                   |               | Risk notables are automatically generated when you run a risk incident rule, which associates risk scores with a system, user, or other risk objects.                                                                                          | object  |                                                                  |
| 💬 Risk Message                     |                   | `message`         |               | A unique message to describe the risk activity, which can use fields from the risk event surrounded by "$".                                                                                                                                    | string  | Suspicious Activity to $domain$                                  |
| 💣 Risk Objects                     |                   | `risk_objects`    |               | A unique message to describe the risk activity, which can use fields from the risk event surrounded by "$". For example: Suspicious Activity to $domain$                                                                                       | array   |                                                                  |
| 🏷️ None                            |                   |                   | `field`       | Splunk field containing the risk object                                                                                                                                                                                                        | string  |                                                                  |
| ❓ None                             |                   |                   | `type`        | The risk object identifier                                                                                                                                                                                                                     | string  |                                                                  |
| 🧮 None                             |                   |                   | `score`       | A number that represents the risk level of a specific risk object. Risk events have a default score that you can modify using risk factors.                                                                                                    | integer |                                                                  |
| 🔪 Risk Objects                     |                   | `threat_objects`  |               | Deviant behavior patterns of a risk object or entity, which indicate a security breach. For example: The Domain threat object tracks the behavior of the domain across all risk objects.                                                       | array   |                                                                  |
| 🏷️ None                            |                   |                   | `field`       | Splunk field containing the threat object                                                                                                                                                                                                      | string  |                                                                  |
| ❓ None                             |                   |                   | `type`        | Identification of the threat object, inspired by https://splunk.github.io/rba/searches/threat_object_types/#other-types                                                                                                                        | string  |                                                                  |
| 🔍 Splunk SPL Detection Query       | `query`           |                   |               | Correlation search in spl language                                                                                                                                                                                                             | string  | | search (code=10 OR code=29 OR code=43) host!="localhost" xqp>5 |
| 🦾 Advanced Edit custom parameters  | `advanced`        |                   |               | Support for any parameter able to edited through Advanced Edit. Ensure that the naming and data inputed is as expected from Splunk.                                                                                                            | object  |                                                                  |

### Template

``

```yaml
  schema: splunk::2.1
  status: 
  #contributors:
    #-
  #threshold: 0
  
  #throttling:
    #fields:
      #-
    #duration: 1h
  
  scheduling:
    #cron: 
    #frequency: 
    #custom_time: 
    lookback: 
  
  #notable:
  
    #event:
      #title: 
      #description: |
        #...
  
    #drilldown:
      #name: 
      #search: |
        #...
  
    #security_domain: 
  
  #risk:
    #message: 
    #risk_objects:
      #- field: 
        #type: 
        #score: 
    #threat_objects:
      #- field: 
        #type: 
  
  query: |
    ...
```

