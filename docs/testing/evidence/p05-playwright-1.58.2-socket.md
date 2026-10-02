# Complete Package Score

This is a Socket report for the package *"npm/playwright@1.58.2"* and its *2* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 98
- Maintenance: 98
- Quality: 99
- Supply Chain: 99
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
| low      | gptAnomaly  |
| low      | urlStrings  |
| -------- | ----------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 65
- Maintenance: 81
- Quality: 77
- Supply Chain: 65
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/playwright-core@1.58.2
- Maintenance: npm/fsevents@2.3.2
- Quality: npm/playwright-core@1.58.2
- Supply Chain: npm/playwright-core@1.58.2
- Vulnerability: npm/fsevents@2.3.2
- License: npm/fsevents@2.3.2

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

| -------- | ---------------- | ---------------------------- |
| Severity | Alert Name       | Example package reporting it |
| -------- | ---------------- | ---------------------------- |
| middle   | gptSecurity      | npm/playwright@1.58.2        |
| middle   | networkAccess    | npm/playwright-core@1.58.2   |
| middle   | shellAccess      | npm/playwright-core@1.58.2   |
| middle   | usesEval         | npm/playwright-core@1.58.2   |
| low      | debugAccess      | npm/playwright-core@1.58.2   |
| low      | dynamicRequire   | npm/playwright-core@1.58.2   |
| low      | envVars          | npm/playwright-core@1.58.2   |
| low      | filesystemAccess | npm/playwright-core@1.58.2   |
| low      | gptAnomaly       | npm/playwright@1.58.2        |
| low      | minifiedFile     | npm/playwright-core@1.58.2   |
| low      | urlStrings       | npm/playwright-core@1.58.2   |
| -------- | ---------------- | ---------------------------- |

