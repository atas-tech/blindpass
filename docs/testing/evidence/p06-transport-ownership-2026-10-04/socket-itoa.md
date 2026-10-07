# Complete Package Score

This is a Socket report for the package *"cargo/itoa@1.0.18"* and its *52* direct/transitive dependencies.

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

- Overall: 36
- Maintenance: 100
- Quality: 89
- Supply Chain: 36
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Maintenance: cargo/shlex@1.3.0
- Quality: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Supply Chain: cargo/winapi-i686-pc-windows-gnu@0.4.0
- Vulnerability: cargo/shlex@1.3.0
- License: cargo/shlex@1.3.0

### Capabilities

These are the capabilities detected in at least one package:

- env
- fs
- net
- shell
- unsafe

### Alerts

These are the alerts found:

| -------- | ---------------- | ---------------------------- |
| Severity | Alert Name       | Example package reporting it |
| -------- | ---------------- | ---------------------------- |
| middle   | hasNativeCode    | cargo/winapi@0.3.9           |
| middle   | installScripts   | cargo/winapi@0.3.9           |
| middle   | networkAccess    | cargo/criterion@0.8.2        |
| middle   | shellAccess      | cargo/autocfg@1.5.0          |
| low      | envVars          | cargo/autocfg@1.5.0          |
| low      | filesystemAccess | cargo/either@1.15.0          |
| low      | gptAnomaly       | cargo/winapi-util@0.1.11     |
| -------- | ---------------- | ---------------------------- |

