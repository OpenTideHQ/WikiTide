

# Traffic Light Protocol

`tlp`



> The Traffic Light Protocol - or short: TLP - was designed with the objective to create a favorable classification scheme for sharing sensitive information while keeping the control over its distribution at the same time.

| 🔑 Id             | 🎫 Name         | 🔬 Description                                                                                                                                                                   | 🌌 Misp           |
|:-----------------|:---------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------|
| TLP:AMBER        | 🟠 amber        | Limited disclosure, recipients can only spread this on a need-to-know basis within their organization and its clients.                                                          | tlp:amber        |
| TLP:AMBER+STRICT | 🟠 amber+strict | Similar to TLP:AMBER, but restricts sharing to the organization only.                                                                                                           | tlp:amber+strict |
| TLP:CLEAR        | ⚪ clear        | Recipients can spread this to the world, there is no limit on disclosure.                                                                                                       | tlp:clear        |
| TLP:GREEN        | 🟢 green        | Limited disclosure, recipients can spread this within their community. Sources may use TLP:GREEN when information is useful to increase awareness within their wider community. | tlp:green        |
| TLP:RED          | 🔴 red          | For the eyes and ears of individual recipients only, no further disclosure.                                                                                                     | tlp:red          |

