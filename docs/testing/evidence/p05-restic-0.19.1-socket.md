# Complete Package Score

This is a Socket report for the package *"golang/github.com/restic/restic@v0.19.1"* and its *97* direct/transitive dependencies.

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
| low      | urlStrings       |
| -------- | ---------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 70
- Maintenance: 75
- Quality: 100
- Supply Chain: 70
- Vulnerability: 70
- License: 50

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: golang/google.golang.org/grpc@v1.81.1
- Maintenance: golang/github.com/kr/fs@v0.1.0
- Quality: golang/github.com/go-ole/go-ole@v1.3.0
- Supply Chain: golang/golang.org/x/oauth2@v0.36.0
- Vulnerability: golang/google.golang.org/grpc@v1.81.1
- License: golang/github.com/russross/blackfriday/v2@v2.1.0

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
| high     | cve                    | golang/google.golang.org/grpc@v1.81.1                                         |
| middle   | gptDidYouMean          | golang/github.com/Backblaze/blazer@v0.7.2                                     |
| middle   | hasNativeCode          | golang/github.com/google/pprof@v0.0.0-20230926050212-f7f687d19a98             |
| middle   | mediumCVE              | golang/go.opentelemetry.io/otel@v1.43.0                                       |
| middle   | networkAccess          | golang/github.com/felixge/httpsnoop@v1.0.4                                    |
| middle   | potentialVulnerability | golang/github.com/pkg/sftp@v1.13.10                                           |
| middle   | shellAccess            | golang/github.com/pkg/profile@v1.7.0                                          |
| middle   | usesEval               | golang/github.com/restic/restic@v0.19.1                                       |
| low      | copyleftLicense        | golang/github.com/hashicorp/golang-lru/v2@v2.0.7                              |
| low      | envVars                | golang/github.com/pkg/profile@v1.7.0                                          |
| low      | filesystemAccess       | golang/github.com/felixge/httpsnoop@v1.0.4                                    |
| low      | gptAnomaly             | golang/github.com/planetscale/vtprotobuf@v0.6.1-0.20240319094008-0393e58bdf10 |
| low      | mildCVE                | golang/go.opentelemetry.io/otel/sdk@v1.43.0                                   |
| low      | nonpermissiveLicense   | golang/github.com/hashicorp/golang-lru/v2@v2.0.7                              |
| low      | unidentifiedLicense    | golang/github.com/russross/blackfriday/v2@v2.1.0                              |
| low      | unmaintained           | golang/github.com/kr/fs@v0.1.0                                                |
| low      | urlStrings             | pypi/sphinx@9.1.0                                                             |
| -------- | ---------------------- | ----------------------------------------------------------------------------- |

