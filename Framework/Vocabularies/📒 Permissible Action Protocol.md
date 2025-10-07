

# Permissible Action Protocol

`pap`



> The Permissible Actions Protocol - or short: PAP - was designed to indicate how the received information can be used.

| 🔑 Id      | 🎫 Name   | 🔬 Description                                                                                                                                                                                            | 🌌 Misp    |
|:----------|:---------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------|
| PAP:AMBER | amber    | Passive cross check. Recipients may use PAP:AMBER information for conducting online checks, like using services provided by third parties (e.g. VirusTotal), or set up a monitoring honeypot.            | PAP:AMBER |
| PAP:GREEN | green    | Active actions allowed. Recipients may use PAP:GREEN information to ping the target, block incoming/outgoing traffic from/to the target or specifically configure honeypots to interact with the target. | PAP:GREEN |
| PAP:RED   | red      | Non-detectable actions only. Recipients may not use PAP:RED information on the network. Only passive actions on logs, that are not detectable from the outside.                                          | PAP:RED   |
| PAP:WHITE | white    | No restrictions in using this information.                                                                                                                                                               | PAP:WHITE |

