# Stock browser acceptance profile

Private AGPL workspace pinning actual `@playwright/mcp@0.0.83`, whose Playwright
and core dependencies are exact `1.64.0-alpha-1790635538000`. This isolates stock
tool dependencies from the private login helper's exact stable 1.58.2 runtime.
The user approved this explicit alpha test profile in
[decision 0006](../../docs/product/decisions/0006-p05-browser-runtime-review.md).
The package and upstream Apache licenses/notices must accompany distribution.

It is installed with lifecycle scripts disabled. No alpha browser download or
supported-client claim is made. A trusted config/channel must bind the tool to
the correct workload context, preserve sandboxing and exclude other local UIDs.
Raw browser endpoints, cookies and authentication headers must never be passed
to the model, argv, normal logs or managed captures. Actual connection,
reconnection and a task in stock clients remain the P05 feasibility gate.
