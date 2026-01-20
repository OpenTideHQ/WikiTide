

# Detection Methodology

`detection.methodology`



> Defines the technical approaches and methods used to implement detection logic.
These methodologies help categorize how a detection rule processes and analyzes data
to identify potential security threats, suspicious activities, or malicious behavior.

Tracking which methodology is used helps understanding if there are any potential gaps in
how signals are implemented, understand which ones are not getting implemented due to
complexity, or even track which types of approach results in the best outcomes.  


| 🔑 Id                                 | 🎫 Name              | 🔬 Description                                                                                                                                                                                                                                                                          |
|:-------------------------------------|:--------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 04c9fabc-1f9c-4526-a523-a4c020a8e145 | Machine Learning    | Leverages machine learning algorithms to analyze data patterns and identifypotential malicious or anomalous behavior that traditional methods might overlook.\                                                                                                                         |
| 43c1bb4d-b74e-4bbd-be22-aae3d301ee51 | Artifacts           | Simple string matching between a set of artifacts (such as known executables)against a log source.                                                                                                                                                                                     |
| 5b418142-1d83-4520-bca0-6b10c2a87b88 | Pattern Matching    | Signature style of detections, where string processing is done to identifyknown simple patterns, for example a set of command line flags                                                                                                                                               |
| 7862439c-3358-4efd-a90a-b142a90bffa3 | Heuristic           | Uses a set of predefined rules or criteria to identify potentially malicious activity based on known indicators or characteristics of threats, without requiring exact matches.                                                                                                        |
| 7f3a9d2b-8c4e-4d3a-9b2e-1f2c3d4e5f6a | Behavioural         | Focuses on understanding and detecting malicious activities by analyzing sequences of actions or behaviors that deviate from normal operational patterns. This approach often involves creating baselines of legitimate behavior and identifying deviations that may indicate threats. |
| 92f1d5fe-e326-40d9-af98-5b0cb334af00 | Anomaly             | Identifies deviations from established baselines or expected patterns in data, which may indicate malicious or suspicious activity.                                                                                                                                                    |
| bb978737-10f4-4873-9c44-140452d003b0 | Frequency Analysis  | Monitors the frequency of specific events or patterns over time to identify unusual spikes or changes that may indicate malicious activity, such as brute force attempts or data exfiltration.                                                                                         |
| cd80b0e9-2656-4af9-94e3-a6e505c8e502 | Event Search        | Filtering logs for specific security-relevant events, such as IDS alerts coming fromnetwork appliances, without significant work.                                                                                                                                                      |
| eb826d84-4611-4d86-a55a-ff434bf59e4d | Statistical         | Uses mathematical and statistical methods to analyze data to identify patterns that may indicate malicious or suspicious activity. This approach often involves aggregating and correlating events to improve detection fidelity.                                                      |
| fb643a20-e3b4-4ed5-a017-87bd6e884bc9 | Threat Intelligence | Leverages external threat intelligence feeds and indicators to identify known malicious activity, including IOCs, TTPs, and threat actor behaviors.                                                                                                                                    |

