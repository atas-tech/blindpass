# Complete Package Score

This is a Socket report for the package *"cargo/cargo-cyclonedx@0.5.7"* and its *139* direct/transitive dependencies.

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

| -------- | ---------- |
| Severity | Alert Name |
| -------- | ---------- |
| low      | envVars    |
| -------- | ---------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 36
- Maintenance: 100
- Quality: 89
- Supply Chain: 36
- Vulnerability: 98
- License: 70

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Maintenance: cargo/idna@0.4.0
- Quality: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Supply Chain: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Vulnerability: cargo/idna@0.4.0
- License: cargo/spdx@0.10.6

### Capabilities

These are the capabilities detected in at least one package:

- env
- fs
- net
- shell
- unsafe
- url

### Alerts

These are the alerts found:

| -------- | -------------------- | ---------------------------- |
| Severity | Alert Name           | Example package reporting it |
| -------- | -------------------- | ---------------------------- |
| middle   | hasNativeCode        | cargo/winapi@0.3.9           |
| middle   | installScripts       | cargo/winapi@0.3.9           |
| middle   | mediumCVE            | cargo/cargo-cyclonedx@0.5.7  |
| middle   | networkAccess        | cargo/quote@1.0.35           |
| middle   | shellAccess          | cargo/time@0.3.36            |
| low      | copyleftLicense      | cargo/spdx@0.10.6            |
| low      | envVars              | cargo/autocfg@1.1.0          |
| low      | filesystemAccess     | cargo/idna@0.4.0             |
| low      | gptAnomaly           | cargo/rand@0.8.5             |
| low      | licenseException     | cargo/rustix@0.38.21         |
| low      | mildCVE              | cargo/rand@0.8.5             |
| low      | nonpermissiveLicense | cargo/spdx@0.10.6            |
| low      | unidentifiedLicense  | cargo/siphasher@0.3.11       |
| low      | urlStrings           | cargo/idna@0.4.0             |
| -------- | -------------------- | ---------------------------- |

