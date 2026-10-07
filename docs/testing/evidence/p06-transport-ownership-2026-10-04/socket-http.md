# Complete Package Score

This is a Socket report for the package *"cargo/http@1.5.0"* and its *54* direct/transitive dependencies.

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

- Overall: 78
- Maintenance: 100
- Quality: 92
- Supply Chain: 78
- Vulnerability: 100
- License: 80

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: cargo/wit-bindgen@0.57.1
- Maintenance: cargo/heck@0.5.0
- Quality: cargo/heck@0.5.0
- Supply Chain: cargo/wit-bindgen@0.57.1
- Vulnerability: cargo/heck@0.5.0
- License: cargo/unicode-xid@0.2.6

### Capabilities

These are the capabilities detected in at least one package:

- env
- fs
- net
- shell
- unsafe

### Alerts

These are the alerts found:

| -------- | ------------------- | ---------------------------- |
| Severity | Alert Name          | Example package reporting it |
| -------- | ------------------- | ---------------------------- |
| middle   | hasNativeCode       | cargo/prettyplease@0.2.37    |
| middle   | installScripts      | cargo/prettyplease@0.2.37    |
| middle   | networkAccess       | cargo/getrandom@0.4.2        |
| middle   | shellAccess         | cargo/wasmparser@0.244.0     |
| low      | envVars             | cargo/prettyplease@0.2.37    |
| low      | filesystemAccess    | cargo/serde@1.0.228          |
| low      | gptAnomaly          | cargo/regex-automata@0.4.14  |
| low      | licenseException    | cargo/wasm-encoder@0.244.0   |
| low      | unidentifiedLicense | cargo/unicode-xid@0.2.6      |
| -------- | ------------------- | ---------------------------- |

