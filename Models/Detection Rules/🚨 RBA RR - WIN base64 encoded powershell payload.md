

# 🚨 RBA_RR - WIN base64 encoded powershell payload

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.



---

`🔑 UUID : 0be66eea-4ae4-4544-811b-52651e20d744` **|** `🏷️ Version : 6` **|** `🗓️ Creation Date : 2024-05-16` **|** `🗓️ Last Modification : 2025-01-09` **|** `👩‍💻 Model author : ec-digit-catch@ec.europa.eu` **|** `🧱 Schema Identifier : mdr::2.0`

## 👁️‍🗨️ Description

> Detect base64 encoded PowerShell payload that could be used to launch 
> a process or a script.
> The detection applies up to 2 levels of encoded payload (a first payload 
> containing a PowerShell command with a second base64 payload).  
> 
> ### Splunk(Sentinel) investigation guidelines ###
> 
> The alert notification contains
> - host(src_host): the host on which the process was launched.
> - src_user: the account used.
> - ParentProcessName(parent_process): the process launching the PS with base64 payload.
> - NewProcessName(process): PS.
> - CommandLine(command_line): the original command line as seen in logs.
> - payload_b64_ascii [and payload_b64]: the first level of encoded payload. 
> They are always present.
> - payload_level2_b64_ascii [and payload_level2_b64] may also be provided 
> if the first level was containing another base64 encoded payload.
> For Sentinel Alert, you have to decode the base64 string present in command_line field,
> using CyberChef or any base64 decoding tool.  
> 
> ### SENTINEL alerts triage ###
> CATCH uses TIDE_LD_005_CSIRC_WL_Win_Base64_Encoded_PS_Payload.csv
> to filter legitimate or benign base64 encoded payloads used by PowerShell 
> on EC Windows devices running on our Azure IaaS & PaaS tenant.
> 
> ### ES-SPLUNK alerts triage ###
> CATCH uses SOC_LT_289_WIN_reviewed_base64_encoded_payload-exclude.csv
> to filter legitimate or benign base64 encoded payloads used by PowerShell 
> on EC Windows devices.
> 

### 🕸️ Relations

🚫 No related objects indexed.

&nbsp;

## ⚠️ Response

| 🌡️ Alert Severity                                                                     | ‍🚒 Alert Handling Team                                 | 👣 Playbook link                                 |
|:--------------------------------------------------------------------------------------|:-------------------------------------------------------|:------------------------------------------------|
| **High** : Needs attention within tight SLAs alongside a comprehensive investigation. | **CSIRC** : Computer Security Incident Response Centre | No playbook was defined for this detection rule |

&nbsp;

## 💽 Configurations


<details>
<summary>Microsoft Sentinel <b>PRODUCTION</b></summary>

>**Status** : `PRODUCTION` - _Deployed in active production environment, potentially raising alerts_
>**Strategy** : `RELEASE` - _Deployment from the default branch (also called trunk, or main branch)_

| Parameter                     | System Config                                 | Description                                                                                                                                                                                                                                                                     | Config                                                                                                                                                                                                                                                                                                                            |
|:------------------------------|:----------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Schema identifier and version |                                               | Identifier of the schema at its current version                                                                                                                                                                                                                                 | `sentinel::2.0`                                                                                                                                                                                                                                                                                                                   |
| 🧊 Entity Mappings             | `entityMappings`                              | Entity mapping is an integral part of the configuration of scheduled query analytics rules. It enriches the rules' output (alerts and incidents) with essential information that serves as the building blocks of any investigative processes and remedial actions that follow. | `{'entity': 'Process', 'mappings': [{'identifier': 'CommandLine', 'column': 'command_line'}]}`, `{'entity': 'Host', 'mappings': [{'identifier': 'HostName', 'column': 'src_host'}, {'identifier': 'DnsDomain', 'column': 'src_nt_domain'}]}`, `{'entity': 'Account', 'mappings': [{'identifier': 'Name', 'column': 'src_user'}]}` |
| ⏱ Recurring Search Interval   | `queryFrequency`                              | Time intervals at which the scheduled search should be ran at, from 5m to up to 14days. Format is X d|h|m. If you create a NRT rule, this value must be removed or commented out.                                                                                               | `1h`                                                                                                                                                                                                                                                                                                                              |
| ⌛ Lookback Configuration      | `queryPeriod`                                 | Duration of logs to search in, up to 14 days. Format is X d|h|m. If you create a NRT rule, this value must be removed or commented out.                                                                                                                                         | `1h`                                                                                                                                                                                                                                                                                                                              |
| ⚖️ Event threshold            | `triggerThreshold`                            | If amount of events is higher than threshold (during the timeframe) the alert is triggered.   ⚠️ If you create a NRT rule, this value must be removed or commented out (NRT rules trigger an alert on the first match)                                                          | 1                                                                                                                                                                                                                                                                                                                                 |
| 🔫 _Missing_                   |                                               | The operation against the threshold that triggers alert rule.  ⚠️ If you create a NRT rule, this value must be removed or commented out (NRT rules trigger an alert on the first match)                                                                                         | `GreaterThan`                                                                                                                                                                                                                                                                                                                     |
| 🔬 Alert Description Format    | `alertDetailsOverride.alertDescriptionFormat` | Free text with field names embedded using the format {{columnName}}. Up to 5000 chars and 3 placeholders                                                                                                                                                                        | `{{description}} `                                                                                                                                                                                                                                                                                                                |
| Alert Suppression             | `suppressionDuration`                         | The duration to wait since last time this alert rule been triggered. Set to "false" to disable all suppression.                                                                                                                                                                 | `False`                                                                                                                                                                                                                                                                                                                           |
| Create Incident               | `incidentConfiguration.createIncident`        | Create incidents from alerts triggered by this analytics rule                                                                                                                                                                                                                   | `True`                                                                                                                                                                                                                                                                                                                            |
| 📣 Event Grouping Details      | `eventGroupingSettings.aggregationKind`       | Configure how rule query results are grouped into alerts.                                                                                                                                                                                                                       | `AlertPerResult`                                                                                                                                                                                                                                                                                                                  |

</details>
&nbsp; 

<details>
<summary>Splunk Enterprise <b>PRODUCTION</b></summary>

>**Status** : `PRODUCTION` - _Deployed in active production environment, potentially raising alerts_
>**Strategy** : `RELEASE` - _Deployment from the default branch (also called trunk, or main branch)_

| Parameter                     | System Config                     | Description                                                                                                                                                                                                                                    | Config                                                                                                   |
|:------------------------------|:----------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------|
| Schema identifier and version |                                   | Identifier of the schema at its current version                                                                                                                                                                                                | `splunk::2.0`                                                                                            |
| ⌛ Throttling Period           | `alert.suppress.period`           | How long do discard new alerts that have the same characteristics (duplicate alerts), based on the fields defined below in hours/days. Default same as scheduling (value = 1h).                                                                | `2h`                                                                                                     |
| 🔖 Throttling Fields           | `alert.suppress.fields`           | Fields to check for matching values in events. Events with the same value for these fields are suppressed.                                                                                                                                     | `host`, `src_user`, `CommandLine`                                                                        |
| ⏱ Recurring Search Interval   |                                   | Time intervals at which the scheduled search should be ran at. Warning: due to implementation details, only the following intervals are allowed for Splunk : 1-59m , 1-23h , 1-30d . For more complex scheduling, use the cron option instead. | `15m`                                                                                                    |
| ⌛ Lookback Configuration      | `dispatch.earliest_time`          | Duration of logs to search in                                                                                                                                                                                                                  | `15m`                                                                                                    |
| 💬 Risk Message                | `action.risk.param._risk_message` | A unique message to describe the risk activity, which can use fields from the risk event surrounded by "\$".                                                                                                                                   | `Suspicious PowerShell Encoded Payload (\$matching_pattern\$) launched by \$src_user\$ on \$orig_host\$` |
| 💣 Risk Objects                |                                   | A unique message to describe the risk activity, which can use fields from the risk event surrounded by "\$". For example: Suspicious Activity to \$domain\$                                                                                    | `{'field': 'src_user', 'type': 'user', 'score': 10}`, `{'field': 'host', 'type': 'system', 'score': 10}` |
| 🔪 Risk Objects                |                                   | Deviant behavior patterns of a risk object or entity, which indicate a security breach. For example: The Domain threat object tracks the behavior of the domain across all risk objects.                                                       | `{'field': 'CommandLine', 'type': 'command'}`                                                            |

</details>
&nbsp; 


### 🔎 Queries


<details>
<summary>Expand to view Microsoft Sentinel <b>PRODUCTION</b> query</summary>

```sql
let Base64EncodedPS = (
_GetWatchlist('CSIRC_WL_005')
| project command_line);
SecurityEvent
//we look for process creation
| where EventID==4688 
| where isnotempty(CommandLine)
//field renaming
    | extend command_line = CommandLine
    | extend src_host = tostring(split(Computer, '.', 0)[0])
    | extend src_user = SubjectUserName
    | extend src_nt_domain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
    | extend user_type = AccountType
    | extend event_source = EventSourceName
    | extend signature = Activity
    | extend process = NewProcessName
    | extend parent_process = ParentProcessName
    | extend subscription_temp = split(_ResourceId, "/subscriptions/")[1]
    | extend subscription_id = split(subscription_temp, "/")[0]
//^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$
| where (command_line has "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or command_line has "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe") and (command_line has "-e" or command_line has "-enc" or command_line has "-EncodedCommand")
| where parent_process !contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\"
| where command_line <> "\"C:\\windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe\" -noninteractive -outputFormat xml -NonInteractive -encodedCommand IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA= -inputFormat xml"
| where command_line !in~ (Base64EncodedPS)
| project
    TimeGenerated,
    src_host,
    command_line,
    src_user,
    src_nt_domain,
    user_type,
    signature,
    process,
    parent_process,
    subscription_id
| extend description = strcat("command_line=\"",command_line,"\" src_host=\"",src_host,"\" src_user=\"",src_user,"\" user_type=\"",user_type,"\" signature=\"",signature,"\" src_nt_domain=\"",src_nt_domain,"\" process=\"",process,"\" parent_process=\"",parent_process,"\" alert_description=\" suspicious bases64 encoded PowerShell Payload launched by ",src_user," from ",src_host,"\"")
```

</details>
&nbsp; 

<details>
<summary>Expand to view Splunk Enterprise <b>PRODUCTION</b> query</summary>

```sql
`win_security_logs` 
    AND TERM(EventID=4688)
    AND NewProcessName IN ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")
    AND ( TERM(C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe) OR TERM(C:\\WINDOWS\\sysWOW64\\WindowsPowerShell\\v1.0\\PowerShell.exe) )
    AND (TERM(-e) OR TERM(-enc) OR TERM(-EncodedCommand)) 
    NOT TERM(C:\\Windows\\CCM\\CcmExec.exe) 
| rex field=CommandLine "(?i)\s+(-e|-enc|-EncodedCommand)\s+(?<payload_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)" 
| where isnotnull(payload_b64) 
| search `exclude(SOC_LT_289_WIN_reviewed_base64_encoded_payload)` 
| `soc_macro_decode_b64(payload_b64)` 
| fields host, ParentProcessName, src_user, payload_b64_ascii, payload_b64, NewProcessName, CommandLine, _time 
| stats count min(_time) as et, max(_time) as lt, values(ParentProcessName) as ParentProcessName, values(payload_b64_ascii) as payload_b64_ascii, values(payload_b64) as payload_b64 by host src_user NewProcessName CommandLine 
| fields host, count, et, lt, ParentProcessName, src_user, payload_b64_ascii, payload_b64, NewProcessName, CommandLine 
| rename payload_* as payloadlevel1_* 
| rex field=payloadlevel1_b64_ascii "(?i)\s?(-e|-enc|-EncodedCommand)\s?(?<payload_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$" 
| search `exclude(SOC_LT_289_WIN_reviewed_base64_encoded_payload)` 
| `soc_macro_decode_b64(payload_b64)` 
| rename payload_* as payload_level2_*, payloadlevel1_* as payload_* 
| rex field=payload_level2_b64_ascii "(?i)\s?(-e|-enc|-EncodedCommand)\s?(?<payload_level3_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$" 
| eval payload_b64_ascii_sanitized=replace(payload_b64_ascii,"\s+\\\"[^\\\"]+\\\"\s+"," ") 
| lookup SOC_LD_339_RBA_powershell_watch_list_risk_score risk_object_command as payload_b64_ascii_sanitized output comment_description as matching_pattern, risk_confidence, trigger_notable 
| eval payload_level2_b64_ascii_sanitized=replace(payload_level2_b64_ascii,"\s+\\\"[^\\\"]+\\\"\s+"," ") 
| lookup SOC_LD_339_RBA_powershell_watch_list_risk_score risk_object_command as payload_level2_b64_ascii_sanitized outputnew comment_description as matching_pattern, risk_confidence, trigger_notable 
| eval RBA_RR_trigger_notable=if(isnotnull(payload_level3_b64) OR trigger_notable==1, 1, null()) 
| eval risk_score_default=10 
| eval risk_score=if(isnotnull(risk_confidence),max(risk_confidence),risk_score_default) 
| eval matching_pattern=if(isnotnull(matching_pattern),matching_pattern,"UNLISTED") 
| fields host, count, RBA_RR_trigger_notable, risk_score, matching_pattern, et, lt, ParentProcessName, src_user, payload_b64_ascii, payload_b64, payload_level2_b64_ascii, payload_level2_b64, NewProcessName, CommandLine, _time 
| `soc_macro_ctime_utc(et)` 
| `soc_macro_ctime_utc(lt)`
```

</details>
&nbsp; 



### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md
- [_2_] https://kqlquery.com/posts/hunting-encoded-powershell/
- [_3_] https://github.com/Javelinblog/PowerShell-Encoded-Commands-Tool/tree/main?tab=readme-ov-file

[1]: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md
[2]: https://kqlquery.com/posts/hunting-encoded-powershell/
[3]: https://github.com/Javelinblog/PowerShell-Encoded-Commands-Tool/tree/main?tab=readme-ov-file

&nbsp;


