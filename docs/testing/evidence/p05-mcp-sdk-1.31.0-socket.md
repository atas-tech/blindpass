# Complete Package Score

This is a Socket report for the package *"npm/@modelcontextprotocol/sdk@1.31.0"* and its *95* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 96
- Maintenance: 96
- Quality: 100
- Supply Chain: 98
- Vulnerability: 100
- License: 100

### Capabilities

These are the capabilities detected in the package itself:

- url

### Alerts for this package

These are the alerts found for the package itself:

| -------- | ----------- |
| Severity | Alert Name  |
| -------- | ----------- |
| middle   | gptSecurity |
| low      | urlStrings  |
| -------- | ----------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 48
- Maintenance: 50
- Quality: 66
- Supply Chain: 66
- Vulnerability: 96
- License: 80

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/hasown@2.0.4
- Maintenance: npm/safer-buffer@2.1.2
- Quality: npm/is-promise@4.0.0
- Supply Chain: npm/side-channel@1.1.1
- Vulnerability: npm/qs@6.14.1
- License: npm/json-schema-typed@8.0.2

### Capabilities

These are the capabilities detected in at least one package:

- env
- eval
- fs
- net
- shell
- unsafe
- url

### Alerts

These are the alerts found:

| -------- | ---------------------- | ------------------------------------ |
| Severity | Alert Name             | Example package reporting it         |
| -------- | ---------------------- | ------------------------------------ |
| high     | socketUpgradeAvailable | npm/safer-buffer@2.1.2               |
| middle   | gptSecurity            | npm/@modelcontextprotocol/sdk@1.31.0 |
| middle   | mediumCVE              | npm/qs@6.14.1                        |
| middle   | networkAccess          | npm/router@2.2.0                     |
| middle   | shellAccess            | npm/cross-spawn@7.0.6                |
| middle   | usesEval               | npm/depd@2.0.0                       |
| low      | debugAccess            | npm/require-from-string@2.0.2        |
| low      | dynamicRequire         | npm/express@5.2.1                    |
| low      | envVars                | npm/which@2.0.2                      |
| low      | filesystemAccess       | npm/isexe@2.0.0                      |
| low      | gptAnomaly             | npm/@modelcontextprotocol/sdk@1.31.0 |
| low      | mildCVE                | npm/qs@6.14.1                        |
| low      | newAuthor              | npm/wrappy@1.0.2                     |
| low      | unmaintained           | npm/path-key@3.1.1                   |
| low      | urlStrings             | npm/@cfworker/json-schema@4.1.1      |
| -------- | ---------------------- | ------------------------------------ |

