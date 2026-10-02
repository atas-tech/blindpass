# Complete Package Score

This is a Socket report for the package *"golang/golang.org/x/crypto@v0.57.0"* and its *4* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 100
- Maintenance: 100
- Quality: 100
- Supply Chain: 100
- Vulnerability: 100
- License: 100

### Capabilities

No capabilities were found in the package.

### Alerts for this package

These are the alerts found for the package itself:

| -------- | ---------------------- |
| Severity | Alert Name             |
| -------- | ---------------------- |
| middle   | networkAccess          |
| middle   | potentialVulnerability |
| middle   | shellAccess            |
| middle   | usesEval               |
| low      | envVars                |
| low      | filesystemAccess       |
| low      | gptAnomaly             |
| -------- | ---------------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 74
- Maintenance: 100
- Quality: 100
- Supply Chain: 74
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: golang/golang.org/x/net@v0.58.0
- Maintenance: golang/golang.org/x/net@v0.58.0
- Quality: golang/golang.org/x/net@v0.58.0
- Supply Chain: golang/golang.org/x/net@v0.58.0
- Vulnerability: golang/golang.org/x/net@v0.58.0
- License: golang/golang.org/x/net@v0.58.0

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

| -------- | ---------------------- | ---------------------------------- |
| Severity | Alert Name             | Example package reporting it       |
| -------- | ---------------------- | ---------------------------------- |
| middle   | hasNativeCode          | golang/golang.org/x/sys@v0.48.0    |
| middle   | networkAccess          | golang/golang.org/x/net@v0.58.0    |
| middle   | potentialVulnerability | golang/golang.org/x/crypto@v0.57.0 |
| middle   | shellAccess            | golang/golang.org/x/net@v0.58.0    |
| middle   | usesEval               | golang/golang.org/x/net@v0.58.0    |
| low      | envVars                | golang/golang.org/x/crypto@v0.57.0 |
| low      | filesystemAccess       | golang/golang.org/x/net@v0.58.0    |
| low      | gptAnomaly             | golang/golang.org/x/crypto@v0.57.0 |
| -------- | ---------------------- | ---------------------------------- |

