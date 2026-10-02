# Complete Package Score

This is a Socket report for the package *"cargo/tokio-rustls@0.26.6"* and its *123* direct/transitive dependencies.

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

There are currently no alerts for this package.

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 12
- Maintenance: 100
- Quality: 89
- Supply Chain: 12
- Vulnerability: 98
- License: 90

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: cargo/r-efi@5.3.0
- Maintenance: cargo/ring@0.17.14
- Quality: cargo/fs_extra@1.3.0
- Supply Chain: cargo/r-efi@5.3.0
- Vulnerability: cargo/time@0.3.41
- License: cargo/r-efi@5.3.0

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

| -------- | -------------------- | ------------------------------------------ |
| Severity | Alert Name           | Example package reporting it               |
| -------- | -------------------- | ------------------------------------------ |
| middle   | gptSecurity          | cargo/aws-lc-sys@0.45.0                    |
| middle   | hasNativeCode        | cargo/ring@0.17.14                         |
| middle   | installScripts       | cargo/ring@0.17.14                         |
| middle   | mediumCVE            | cargo/time@0.3.41                          |
| middle   | networkAccess        | cargo/r-efi@5.3.0                          |
| middle   | shellAccess          | cargo/ring@0.17.14                         |
| middle   | usesEval             | cargo/ring@0.17.14                         |
| low      | envVars              | cargo/ring@0.17.14                         |
| low      | filesystemAccess     | cargo/ring@0.17.14                         |
| low      | gptAnomaly           | cargo/ring@0.17.14                         |
| low      | licenseException     | cargo/wasi@0.11.1%2Bwasi-snapshot-preview1 |
| low      | nonpermissiveLicense | cargo/webpki-roots@1.0.9                   |
| -------- | -------------------- | ------------------------------------------ |
