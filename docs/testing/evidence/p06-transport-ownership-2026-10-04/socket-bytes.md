# Complete Package Score

This is a Socket report for the package *"cargo/bytes@1.12.1"* and its *49* direct/transitive dependencies.

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

- Overall: 70
- Maintenance: 100
- Quality: 92
- Supply Chain: 70
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: cargo/portable-atomic@1.11.1
- Maintenance: cargo/tracing@0.1.41
- Quality: cargo/tracing@0.1.41
- Supply Chain: cargo/portable-atomic@1.11.1
- Vulnerability: cargo/tracing@0.1.41
- License: cargo/tracing@0.1.41

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
| middle   | hasNativeCode    | cargo/valuable@0.1.1         |
| middle   | installScripts   | cargo/valuable@0.1.1         |
| middle   | networkAccess    | cargo/quote@1.0.42           |
| middle   | shellAccess      | cargo/tracing-core@0.1.34    |
| low      | envVars          | cargo/valuable@0.1.1         |
| low      | filesystemAccess | cargo/tracing-core@0.1.34    |
| low      | gptAnomaly       | cargo/windows@0.61.3         |
| -------- | ---------------- | ---------------------------- |

