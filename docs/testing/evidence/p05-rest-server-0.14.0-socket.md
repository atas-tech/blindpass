# Complete Package Score

This is a Socket report for the package *"golang/github.com/restic/rest-server@v0.14.0"* and its *19* direct/transitive dependencies.

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
| low      | filesystemAccess |
| -------- | ---------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 25
- Maintenance: 75
- Quality: 100
- Supply Chain: 71
- Vulnerability: 25
- License: 80

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: golang/golang.org/x/crypto@v0.38.0
- Maintenance: golang/github.com/beorn7/perks@v1.0.1
- Quality: golang/github.com/minio/sha256-simd@v1.0.1
- Supply Chain: golang/github.com/prometheus/client_golang@v1.22.0
- Vulnerability: golang/golang.org/x/crypto@v0.38.0
- License: golang/github.com/coreos/go-systemd/v22@v22.5.0

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

| -------- | ---------------------- | ----------------------------------------------- |
| Severity | Alert Name             | Example package reporting it                    |
| -------- | ---------------------- | ----------------------------------------------- |
| critical | criticalCVE            | golang/golang.org/x/crypto@v0.38.0              |
| high     | cve                    | golang/golang.org/x/crypto@v0.38.0              |
| middle   | hasNativeCode          | golang/golang.org/x/sys@v0.33.0                 |
| middle   | mediumCVE              | golang/golang.org/x/crypto@v0.38.0              |
| middle   | networkAccess          | golang/github.com/felixge/httpsnoop@v1.0.4      |
| middle   | potentialVulnerability | golang/golang.org/x/crypto@v0.38.0              |
| middle   | shellAccess            | golang/github.com/coreos/go-systemd/v22@v22.5.0 |
| middle   | usesEval               | golang/github.com/minio/sha256-simd@v1.0.1      |
| low      | envVars                | golang/github.com/coreos/go-systemd/v22@v22.5.0 |
| low      | filesystemAccess       | golang/github.com/restic/rest-server@v0.14.0    |
| low      | gptAnomaly             | golang/github.com/prometheus/procfs@v0.15.1     |
| low      | unidentifiedLicense    | golang/github.com/coreos/go-systemd/v22@v22.5.0 |
| low      | unmaintained           | golang/github.com/beorn7/perks@v1.0.1           |
| -------- | ---------------------- | ----------------------------------------------- |

