# Complete Package Score

This is a Socket report for the package *"npm/@modelcontextprotocol/server-legacy@2.2.0"* and its *76* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 50
- Maintenance: 50
- Quality: 85
- Supply Chain: 98
- Vulnerability: 100
- License: 100

### Capabilities

These are the capabilities detected in the package itself:

- env
- net
- url

### Alerts for this package

These are the alerts found for the package itself:

| -------- | ------------- |
| Severity | Alert Name    |
| -------- | ------------- |
| middle   | deprecated    |
| middle   | networkAccess |
| low      | envVars       |
| low      | urlStrings    |
| -------- | ------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 48
- Maintenance: 50
- Quality: 66
- Supply Chain: 66
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/hasown@2.0.4
- Maintenance: npm/safer-buffer@2.1.2
- Quality: npm/is-promise@4.0.0
- Supply Chain: npm/side-channel@1.1.1
- Vulnerability: npm/inherits@2.0.4
- License: npm/inherits@2.0.4

### Capabilities

These are the capabilities detected in at least one package:

- env
- eval
- fs
- net
- unsafe
- url

### Alerts

These are the alerts found:

| -------- | ---------------------- | --------------------------------------------- |
| Severity | Alert Name             | Example package reporting it                  |
| -------- | ---------------------- | --------------------------------------------- |
| high     | socketUpgradeAvailable | npm/safer-buffer@2.1.2                        |
| middle   | deprecated             | npm/@modelcontextprotocol/server-legacy@2.2.0 |
| middle   | networkAccess          | npm/router@2.2.0                              |
| middle   | usesEval               | npm/depd@2.0.0                                |
| low      | debugAccess            | npm/on-finished@2.4.1                         |
| low      | dynamicRequire         | npm/express@5.2.1                             |
| low      | envVars                | npm/depd@2.0.0                                |
| low      | filesystemAccess       | npm/etag@1.8.1                                |
| low      | gptAnomaly             | npm/ipaddr.js@1.9.1                           |
| low      | newAuthor              | npm/wrappy@1.0.2                              |
| low      | unmaintained           | npm/@modelcontextprotocol/server-legacy@2.2.0 |
| low      | urlStrings             | npm/object-inspect@1.13.4                     |
| -------- | ---------------------- | --------------------------------------------- |

