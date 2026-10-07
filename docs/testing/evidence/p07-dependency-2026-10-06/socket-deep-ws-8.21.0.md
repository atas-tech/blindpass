# Complete Package Score

This is a Socket report for the package *"npm/ws@8.21.0"* and its *3* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 90
- Maintenance: 90
- Quality: 100
- Supply Chain: 98
- Vulnerability: 100
- License: 100

### Capabilities

These are the capabilities detected in the package itself:

- env
- net

### Alerts for this package

These are the alerts found for the package itself:

| -------- | ------------- |
| Severity | Alert Name    |
| -------- | ------------- |
| middle   | networkAccess |
| low      | envVars       |
| low      | gptAnomaly    |
| -------- | ------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 80
- Maintenance: 80
- Quality: 82
- Supply Chain: 98
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/bufferutil@4.1.0
- Maintenance: npm/bufferutil@4.1.0
- Quality: npm/utf-8-validate@6.0.6
- Supply Chain: npm/ws@8.21.0
- Vulnerability: npm/node-gyp-build@4.8.4
- License: npm/node-gyp-build@4.8.4

### Capabilities

These are the capabilities detected in at least one package:

- env
- fs
- net

### Alerts

These are the alerts found:

| -------- | ---------------- | ---------------------------- |
| Severity | Alert Name       | Example package reporting it |
| -------- | ---------------- | ---------------------------- |
| middle   | hasNativeCode    | npm/bufferutil@4.1.0         |
| middle   | networkAccess    | npm/ws@8.21.0                |
| low      | envVars          | npm/ws@8.21.0                |
| low      | filesystemAccess | npm/node-gyp-build@4.8.4     |
| low      | gptAnomaly       | npm/ws@8.21.0                |
| -------- | ---------------- | ---------------------------- |

