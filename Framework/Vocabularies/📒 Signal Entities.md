

# Signal Entities

`signal.entities`

| ID      | Name             | Description              |
|:--------|:-----------------|:-------------------------|
| host    | Host Entities    | Host Related Entities    |
| network | Network Entities | Network Related Entities |
| cloud   | Cloud Entities   | Cloud Related Entities   |

> Represents the core objects or attributes that a detection signal focuses on.
These entities are critical for identifying, grouping, and analyzing security
events. They align with common detection methodologies and frameworks like
MITRE ATT&CK.


| 🔑 Id                                 | 🎫 Name             | 🔬 Description                                                                                                                                                                                            |  Tide.vocab.stages   |
|:-------------------------------------|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------|
| 004ab636-1a3a-43e1-bab0-ed171f8df417 | Authentication     | Represents an authentication attempt, including the user, source IP, and success or failure status. Authentication events are critical for detecting brute force attacks or unauthorized access.         | ['host', 'cloud']    |
| 0d80566c-88a9-4815-85d9-871ded46b88c | Protocol           | Represents a network protocol, such as HTTP, HTTPS, FTP, or SMB. Protocols are often analyzed to identify unusual or malicious activity.                                                                 | network              |
| 1e3976f7-ece0-4601-ba6b-be805aa27f84 | Geolocation        | Represents the geographic location of an IP address or device. Geolocation data is often used to detect anomalies, such as logins from unexpected regions.                                               | host                 |
| 20ab1a7b-ccba-408a-ae2f-37c130a21a24 | API Call           | Represents an API call, including its endpoint, parameters, and response. API calls are often analyzed to detect unauthorized access or data exfiltration.                                               | ['network', 'cloud'] |
| 39d5e5fa-d7d8-4617-9eb0-a31e61b78d49 | Account            | Represents a user account entity, including local, domain, or cloud-basedaccounts.                                                                                                                       | ['host', 'cloud']    |
| 3a13580e-2959-4729-afea-07f6fac6ba71 | Service            | Represents a system service, including its name, status, and associated processes. Services are often analyzed to detect unauthorized or malicious services running on a host.                           | host                 |
| 44156a4d-2b7b-4835-b6c3-9f329b81dbd0 | User               | Represents an individual user, including their identity and associatedattributes.                                                                                                                        | ['host', 'cloud']    |
| 46673041-bbbb-4fd1-87fc-d89ac4c4546f | Resource           | Represents a cloud-based resource, such as virtual machines, storage buckets, or serverless functions. These resources are often targeted in cloud environments for unauthorized access or exploitation. | cloud                |
| 6ac71d2e-f8f0-4353-8a29-d1e0c2875acb | Software           | Represents a software package, including its name, version, and installation source. Software packages are often analyzed to detect unauthorized or vulnerable software.                                 | host                 |
| 7860dfeb-7baf-4bee-b8a2-ef6fa76892aa | Scheduled Task     | Represents a scheduled task or cron job, including its configuration and execution details. Scheduled tasks are often used by attackers for persistence.                                                 | host                 |
| 7d112622-4a2c-434a-b80a-f3998dfb090b | URL                | Represents a Uniform Resource Locator (URL), often used in web-basedattacks or phishing campaigns.                                                                                                       | network              |
| 7da2b6bf-62ac-4e9e-ab5f-187b5b1407e0 | Session            | Represents a user or system session, including session IDs and associated activities. Sessions are often analyzed to detect unauthorized access or unusual behavior.                                     | network              |
| 7e868645-b4f7-4901-8701-023f05c24799 | Network Connection | Represents a network connection, including source and destination IPs, ports, and protocols. This entity is critical for detecting suspicious or unauthorized communication between systems.             | network              |
| 8ba0fe1b-74fc-4417-87b0-788bc7e1b227 | File               | Represents a file on a system, including its name, path, and attributes.                                                                                                                                 | host                 |
| aca091fd-d169-49b3-8d92-3c11616b66db | Command Line       | Represents the command line arguments used to execute a process.                                                                                                                                         | host                 |
| aeba3e93-c156-41a2-9b5a-85224e17fdda | Permissions        | Leverages a set of allowed actions                                                                                                                                                                       | ['cloud', 'host']    |
| c23fbfd5-0dd5-4dca-bc63-5e08a7a83c22 | File Hash          | Represents the hash of a file, used to uniquely identify its contents.                                                                                                                                   | host                 |
| c2ed0ba9-1ff0-403e-914e-b72a5224b234 | DNS Query          | Represents a DNS query, including the requested domain and response. DNS queries are often analyzed to detect malicious domains or command-and-control (C2) activity.                                    | network              |
| c7598e49-6c2e-459e-a354-8c326752097c | Port               | Represents a network port, including source and destination ports. Ports are often used to detect unauthorized services or unusual traffic patterns.                                                     | network              |
| c7bad96d-6e37-4d8d-8373-ce5489958068 | Hostname           | Represents the name of a host or device in the network.                                                                                                                                                  | host                 |
| ca44ed3e-d363-4089-a155-50c716b8400f | Certificate        | Represents a digital certificate, including its issuer, validity, and usage. Certificates are often analyzed to detect spoofing or expired credentials.                                                  | network              |
| cb7e78f2-c4cd-43fb-b3ab-cb0d22c55424 | Registry Key/Value | Represents a Windows registry key, including its path and associatedvalues.                                                                                                                              | host                 |
| d187990e-cebb-41cd-94d3-828beb75bdde | Email              | Represents an email entity, including sender, recipient, subject, and message content. Emails are often used in phishing attacks or as a vector for delivering malicious payloads.                       | ['network', 'host']  |
| d9dd557d-7438-4e4f-8e10-f021c1da2a16 | Device Type        | Represents the type of device, such as a workstation, server, mobile device, or IoT device. This entity helps in identifying and categorizing assets.                                                    | host                 |
| e6940ca8-54b5-4f4e-8b41-4412547c09aa | Domain             | Represents a domain name, including those used in network communicationsor as part of URLs.                                                                                                              | host                 |
| f25eef26-c9df-44ae-9ae2-030943600f93 | IP Address         | Represents an IPv4 or IPv6 address associated with a host or networkconnection.                                                                                                                          | network              |
| f73506f3-fdf9-473c-8286-ad16ae56ddf6 | Process            | Represents a running process on a host, including its attributes likeprocess ID and command line.                                                                                                        | host                 |
| ff069dd1-cfd0-494c-908f-3c295c5dd33f | Token              | Represents an authentication or access token, such as OAuth tokens or API keys. Tokens are often analyzed to detect unauthorized access or misuse.                                                       | ['host', 'cloud']    |

