

# Vector Chaining Relationship

`chaining_relations`

| ID        | Name         | Description                                                                    |
|:----------|:-------------|:-------------------------------------------------------------------------------|
| sequence  | 🎞️ Sequence  | Relative time or ordering of TVM execution                                     |
| atomicity | ⚛️ Atomicity | TVMs may overlap in concepts, with a scope or granularity hierarchy            |
| support   | ⚓ Supportive | TVMs which successful execution allows other TVMs to be more easily performed, |
|           |              | or produce larger impact.                                                      |

> Logical relation category between two threat vectors, building block of TVM Chaining

| 🔑 Id    | 🎫 Name        | 🔬 Description                                                                  |  Tide.vocab.stages   |  Tide.vocab.relation.type   |
|:--------|:--------------|:-------------------------------------------------------------------------------|:---------------------|:----------------------------|
| CHN0001 | ⏭️ preceeds   | The following TVM is occuring **AFTER** this TVM object has been performed.    | sequence             | from                        |
| CHN0002 | ⏮️ succeeds   | The following TVM is occuring **BEFORE** this TVM object has been performed.   | sequence             | to                          |
| CHN0010 | 👑 implemented | The following TVM is being performed in this TVM object in a more specific way | atomicity            | from                        |
| CHN0011 | ♟️ implements | The following TVM is performing this TVM object in a more specific way         | atomicity            | to                          |
| CHN0020 | ⚡ enabled     | The following TVM is allowed by this TVM object to be more easily performed    | support              | from                        |
| CHN0021 | 🙌 enabling    | The following TVM is allowing this TVM object to be more easily performed      | support              | to                          |
| CHN0022 | 🤝 synergize   | Both TVM supports each other in performing adversary operations                | support              | bidirectional               |

