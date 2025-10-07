

# Unified Kill Chain

`killchain`

_This vocabulary contains multiple stages :_ 

- Initial Foothold
- Network Propagation
- Action on Objectives

> Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

| 🔑 Id    | 🎫 Name                 | 🔬 Description                                                                                        |  Tide.vocab.stages   | 🌌 Misp                                                        |
|:--------|:-----------------------|:-----------------------------------------------------------------------------------------------------|:---------------------|:--------------------------------------------------------------|
| UKC0001 | 🔭 Reconnaissance       | Researching, identifying and selecting targets using active or passive reconnaissance.               | Initial Foothold     | unified-kill-chain:Initial Foothold="reconnaissance"          |
| UKC0002 | 💣 Weaponization        | Preparatory activities aimed at setting up the infrastructure required for the attack.               | Initial Foothold     | unified-kill-chain:Initial Foothold="weaponization"           |
| UKC0003 | 📦 Delivery             | Techniques resulting in the transmission of a weaponized object to the targeted environment.         | Initial Foothold     | unified-kill-chain:Initial Foothold="delivery"                |
| UKC0004 | 🪝 Social Engineering   | Techniques aimed at the manipulation of people to perform unsafe actions.                            | Initial Foothold     | unified-kill-chain:Initial Foothold="social-engineering"      |
| UKC0005 | 💥 Exploitation         | Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution. | Initial Foothold     | unified-kill-chain:Initial Foothold="exploitation"            |
| UKC0006 | 🔐 Persistence          | Any access, action or change to a system that gives an attacker persistent presence on the system.   | Initial Foothold     | unified-kill-chain:Initial Foothold="persistence"             |
| UKC0007 | 🏃🏽 Defense Evasion     | Techniques an attacker may specifically use for evading detection or avoiding other defenses.        | Initial Foothold     | unified-kill-chain:Initial Foothold="defense-evasion"         |
| UKC0008 | 🕹️ Command & Control   | Techniques that allow attackers to communicate with controlled systems within a target network.      | Initial Foothold     | unified-kill-chain:Initial Foothold="command-control"         |
| UKC0009 | 🌐 Pivoting             | Tunneling traffic through a controlled system to other systems that are not directly accessible.     | Network Propagation  | unified-kill-chain:Network Propagation="pivoting"             |
| UKC0010 | 🧭 Discovery            | Techniques that allow an attacker to gain knowledge about a system and its network environment.      | Network Propagation  | unified-kill-chain:Network Propagation="discovery"            |
| UKC0011 | 🥸 Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network.    | Network Propagation  | unified-kill-chain:Network Propagation="privilege-escalation" |
| UKC0012 | ⚡ Execution            | Techniques that result in execution of attacker-controlled code on a local or remote system.         | Network Propagation  | unified-kill-chain:Network Propagation="execution"            |
| UKC0013 | 🔑 Credential Access    | Techniques resulting in the access of, or control over, system, service or domain credentials.       | Network Propagation  | unified-kill-chain:Network Propagation="credential-access"    |
| UKC0014 | 🌐 Lateral Movement     | Techniques that enable an adversary to horizontally access and control other remote systems.         | Network Propagation  | unified-kill-chain:Network Propagation="lateral-movement"     |
| UKC0015 | 🗃️ Collection          | Techniques used to identify and gather data from a target network prior to exfiltration.             | Action on Objectives | unified-kill-chain:Action on Objectives="collection"          |
| UKC0016 | 📨 Exfiltration         | Techniques that result or aid in an attacker removing data from a target network.                    | Action on Objectives | unified-kill-chain:Action on Objectives="exfiltration"        |
| UKC0017 | 💥 Impact               | Techniques aimed at manipulating, interrupting or destroying the target system or data.              | Action on Objectives | unified-kill-chain:Action on Objectives="impact"              |
| UKC0018 | 🎯 Objectives           | Socio-technical objectives of an attack that are intended to achieve a strategic goal.               | Action on Objectives | unified-kill-chain:Action on Objectives="objectives"          |

