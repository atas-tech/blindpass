# Complete Package Score

This is a Socket report for the package *"npm/fast-uri@3.1.8"* and its *4* direct/transitive dependencies.

It will show you the shallow score for just the package itself and a deep score for all the transitives combined. Additionally you can see which capabilities were found and the top alerts as well as a package that was responsible for it.

The report should give you a good insight into the status of this package.

## Package itself

Here are results for the package itself (excluding data from dependencies).

### Shallow Score

This score is just for the package itself:

- Overall: 97
- Maintenance: 97
- Quality: 100
- Supply Chain: 99
- Vulnerability: 100
- License: 100

### Capabilities

These are the capabilities detected in the package itself:

- url

### Alerts for this package

These are the alerts found for the package itself:

| -------- | ---------- |
| Severity | Alert Name |
| -------- | ---------- |
| low      | urlStrings |
| -------- | ---------- |

## Transitive Package Results

Here are results for the package and its direct/transitive dependencies.

### Deep Score

This score represents the package and and its direct/transitive dependencies:
The function used to calculate the values in aggregate is: *"min"*

- Overall: 75
- Maintenance: 75
- Quality: 98
- Supply Chain: 92
- Vulnerability: 100
- License: 100

### Capabilities

These are the packages with the lowest recorded score. If there is more than one with the lowest score, just one is shown here. This may help you figure out the source of low scores.

- Overall: npm/uri-js@4.4.1
- Maintenance: npm/uri-js@4.4.1
- Quality: npm/tinybench@5.1.0
- Supply Chain: npm/benchmark@1.0.0
- Vulnerability: npm/uri-js@4.4.1
- License: npm/uri-js@4.4.1

### Capabilities

These are the capabilities detected in at least one package:

- eval
- url

### Alerts

These are the alerts found:

| -------- | ------------- | ---------------------------- |
| Severity | Alert Name    | Example package reporting it |
| -------- | ------------- | ---------------------------- |
| middle   | missingAuthor | npm/benchmark@1.0.0          |
| middle   | usesEval      | npm/benchmark@1.0.0          |
| low      | minifiedFile  | npm/tinybench@5.1.0          |
| low      | unmaintained  | npm/fast-uri@3.1.8           |
| low      | urlStrings    | npm/benchmark@1.0.0          |
| -------- | ------------- | ---------------------------- |

