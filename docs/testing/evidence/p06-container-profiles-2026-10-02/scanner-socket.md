# Complete Package Score

This is a Socket report for the package *"golang/github.com/docker/buildkit-syft-scanner@v1.12.0"* and its *282* direct/transitive dependencies.

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

| -------- | ------------------- |
| Severity | Alert Name          |
| -------- | ------------------- |
| middle   | usesEval            |
| low      | envVars             |
| low      | filesystemAccess    |
| low      | unidentifiedLicense |
| -------- | ------------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 50
- Maintenance: 50
- Quality: 86
- Supply Chain: 70
- Vulnerability: 77
- License: 50

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: golang/github.com/json-iterator/go@v1.1.12
- Maintenance: golang/github.com/json-iterator/go@v1.1.12
- Quality: npm/lodash@4.17.21
- Supply Chain: golang/golang.org/x/oauth2@v0.36.0
- Vulnerability: golang/google.golang.org/grpc@v1.82.1
- License: golang/github.com/xi2/xz@v0.0.0-20171230120015-48954b6210f8

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

| -------- | ---------------------- | ------------------------------------------------------------------------- |
| Severity | Alert Name             | Example package reporting it                                              |
| -------- | ---------------------- | ------------------------------------------------------------------------- |
| high     | cve                    | npm/lodash@4.17.21                                                        |
| middle   | deprecated             | golang/github.com/json-iterator/go@v1.1.12                                |
| middle   | gptSecurity            | golang/github.com/ProtonMail/go-crypto@v1.4.1                             |
| middle   | hasNativeCode          | golang/github.com/blakesmith/ar@v0.0.0-20190502131153-809d4375e1fb        |
| middle   | mediumCVE              | npm/lodash@4.17.21                                                        |
| middle   | networkAccess          | golang/github.com/pelletier/go-toml@v1.9.5                                |
| middle   | potentialVulnerability | golang/github.com/nix-community/go-nix@v0.0.0-20250101154619-4bdde671e0a1 |
| middle   | shellAccess            | golang/github.com/DataDog/zstd@v1.5.5                                     |
| middle   | usesEval               | npm/lodash@4.17.21                                                        |
| low      | copyleftLicense        | golang/github.com/hashicorp/go-cleanhttp@v0.5.2                           |
| low      | envVars                | golang/github.com/DataDog/zstd@v1.5.5                                     |
| low      | filesystemAccess       | golang/github.com/json-iterator/go@v1.1.12                                |
| low      | gptAnomaly             | golang/github.com/docker/buildkit-syft-scanner@v1.12.0                    |
| low      | mildCVE                | golang/go.opentelemetry.io/otel/sdk@v1.43.0                               |
| low      | nonpermissiveLicense   | golang/github.com/hashicorp/go-cleanhttp@v0.5.2                           |
| low      | unidentifiedLicense    | golang/gopkg.in/yaml.v3@v3.0.1                                            |
| low      | unmaintained           | golang/github.com/json-iterator/go@v1.1.12                                |
| low      | urlStrings             | npm/lodash@4.17.21                                                        |
| -------- | ---------------------- | ------------------------------------------------------------------------- |
