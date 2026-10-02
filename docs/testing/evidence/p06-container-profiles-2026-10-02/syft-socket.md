# Complete Package Score

This is a Socket report for the package *"golang/github.com/anchore/syft@v1.51.0"* and its *915* direct/transitive dependencies.

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

| -------- | -------------------- |
| Severity | Alert Name           |
| -------- | -------------------- |
| middle   | gptSecurity          |
| middle   | hasNativeCode        |
| middle   | networkAccess        |
| middle   | shellAccess          |
| middle   | usesEval             |
| low      | copyleftLicense      |
| low      | envVars              |
| low      | filesystemAccess     |
| low      | gptAnomaly           |
| low      | nonpermissiveLicense |
| low      | urlStrings           |
| -------- | -------------------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 25
- Maintenance: 50
- Quality: 50
- Supply Chain: 36
- Vulnerability: 25
- License: 50

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/form-data@2.3.3
- Maintenance: npm/safe-buffer@5.1.2
- Quality: npm/sorted-object@2.0.1
- Supply Chain: maven/junit/junit@4.12
- Vulnerability: npm/form-data@2.3.3
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

| -------- | ------------------------ | ------------------------------------------------------------------ |
| Severity | Alert Name               | Example package reporting it                                       |
| -------- | ------------------------ | ------------------------------------------------------------------ |
| critical | criticalCVE              | npm/form-data@2.3.3                                                |
| high     | cve                      | npm/brace-expansion@1.1.11                                         |
| high     | socketUpgradeAvailable   | npm/safe-buffer@5.1.2                                              |
| high     | unresolvedYarnDependency | golang/github.com/anchore/syft@v1.51.0                             |
| middle   | deprecated               | npm/uuid@3.4.0                                                     |
| middle   | gptDidYouMean            | npm/sorted-object@2.0.1                                            |
| middle   | gptSecurity              | golang/github.com/ProtonMail/go-crypto@v1.4.1                      |
| middle   | hasNativeCode            | golang/github.com/blakesmith/ar@v0.0.0-20190502131153-809d4375e1fb |
| middle   | mediumCVE                | npm/tough-cookie@2.5.0                                             |
| middle   | miscLicenseIssues        | gem/unicorn@4.8.3                                                  |
| middle   | networkAccess            | npm/tough-cookie@2.5.0                                             |
| middle   | potentialVulnerability   | npm/eslint-template-visitor@2.3.2                                  |
| middle   | shellAccess              | npm/cross-spawn@7.0.3                                              |
| middle   | trivialPackage           | npm/has-flag@3.0.0                                                 |
| middle   | usesEval                 | npm/ajv@6.12.6                                                     |
| low      | copyleftLicense          | golang/github.com/hashicorp/go-cleanhttp@v0.5.2                    |
| low      | debugAccess              | npm/resolve-from@4.0.0                                             |
| low      | dynamicRequire           | npm/require-directory@2.1.1                                        |
| low      | envVars                  | npm/which@2.0.2                                                    |
| low      | filesystemAccess         | npm/glob@7.2.3                                                     |
| low      | gptAnomaly               | npm/which@2.0.2                                                    |
| low      | mildCVE                  | npm/brace-expansion@1.1.11                                         |
| low      | minifiedFile             | npm/esquery@1.4.0                                                  |
| low      | newAuthor                | npm/uuid@3.4.0                                                     |
| low      | noLicenseFound           | gem/minitest@5.3.4                                                 |
| low      | nonpermissiveLicense     | npm/npm@6.14.6                                                     |
| low      | unidentifiedLicense      | golang/gopkg.in/yaml.v3@v3.0.1                                     |
| low      | unmaintained             | npm/path-key@3.1.1                                                 |
| low      | urlStrings               | npm/glob@7.2.3                                                     |
| -------- | ------------------------ | ------------------------------------------------------------------ |
