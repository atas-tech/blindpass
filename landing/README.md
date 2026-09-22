# BlindPass landing page

A standalone HTML, CSS and JavaScript landing page for BlindPass. The page distinguishes existing encrypted provisioning from the proposed Linux/browser pilot and includes an explicitly simulated approval workflow. It submits no data and connects to no application backend.

Serve the authored static files from the repository root:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory landing/dist
```

Open `http://127.0.0.1:4173`. No dependency installation or build is required. The page can also be opened directly from [dist/index.html](dist/index.html).

Product copy follows the [roadmap](../docs/product/Roadmap.md) and [specification](../docs/product/Specification.md). Edit the HTML, stylesheet and script directly in `dist/`; this directory contains authored source, not disposable build output. The font is the existing Inter asset reused from the browser UI.
