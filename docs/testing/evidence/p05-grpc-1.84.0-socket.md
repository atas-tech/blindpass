# Complete Package Score

This is a Socket report for the package *"golang/google.golang.org/grpc@v1.84.0"* and its *42* direct/transitive dependencies.

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

| -------- | ---------------- |
| Severity | Alert Name       |
| -------- | ---------------- |
| middle   | networkAccess    |
| middle   | shellAccess      |
| middle   | usesEval         |
| low      | envVars          |
| low      | filesystemAccess |
| low      | gptAnomaly       |
| -------- | ---------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 70
- Maintenance: 100
- Quality: 100
- Supply Chain: 70
- Vulnerability: 98
- License: 80

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: golang/golang.org/x/oauth2@v0.36.0
- Maintenance: golang/github.com/go-logr/stdr@v1.2.2
- Quality: golang/github.com/go-logr/stdr@v1.2.2
- Supply Chain: golang/golang.org/x/oauth2@v0.36.0
- Vulnerability: golang/go.opentelemetry.io/otel/sdk@v1.44.0
- License: golang/gonum.org/v1/gonum@v0.17.0

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

| -------- | ---------------------- | ----------------------------------------------------------------------------- |
| Severity | Alert Name             | Example package reporting it                                                  |
| -------- | ---------------------- | ----------------------------------------------------------------------------- |
| middle   | hasNativeCode          | golang/golang.org/x/sys@v0.47.0                                               |
| middle   | networkAccess          | golang/google.golang.org/grpc@v1.84.0                                         |
| middle   | potentialVulnerability | golang/gonum.org/v1/gonum@v0.17.0                                             |
| middle   | shellAccess            | golang/github.com/golang/protobuf@v1.5.4                                      |
| middle   | usesEval               | golang/github.com/google/uuid@v1.6.0                                          |
| low      | envVars                | golang/github.com/planetscale/vtprotobuf@v0.6.1-0.20240319094008-0393e58bdf10 |
| low      | filesystemAccess       | golang/github.com/golang/protobuf@v1.5.4                                      |
| low      | gptAnomaly             | golang/github.com/planetscale/vtprotobuf@v0.6.1-0.20240319094008-0393e58bdf10 |
| low      | mildCVE                | golang/go.opentelemetry.io/otel/sdk@v1.44.0                                   |
| low      | unidentifiedLicense    | golang/gonum.org/v1/gonum@v0.17.0                                             |
| low      | urlStrings             | golang/gonum.org/v1/gonum@v0.17.0                                             |
| -------- | ---------------------- | ----------------------------------------------------------------------------- |

