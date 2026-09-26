# Landing reel source

Source for the 15-second motion reel embedded in the landing page's "In motion" section ([../dist/assets/blindpass-reel.mp4](../dist/assets/blindpass-reel.mp4) and its poster). Nothing here is published; the Pages deploy uploads only `landing/dist`.

| File | Role |
|---|---|
| [reel.html](reel.html) | The animation: a deterministic `render(t)` timeline for 0–15 s at 1920×1080. Open it in a browser for a live, looping preview, or add `?t=7.9` to hold one moment. |
| [score.py](score.py) | The soundtrack, synthesized with numpy. It uses no samples or licensed audio, and its cue sheet mirrors the times in `reel.html`. |
| [capture.cjs](capture.cjs) | Screenshots `../dist/index.html` at 2× into `build/page2x.jpg` and records element geometry in `build/geom.json`. |
| [frames.cjs](frames.cjs) | Renders `reel.html` to 1,800 PNG frames at 120 fps. It is resumable. |
| [render.sh](render.sh) | Runs all of the above, encodes the master and web cuts, and copies the web cut and poster into `../dist/assets`. |

## Rendering

Requirements: the workspace `npm install` (for `@playwright/test` and its Chromium), `ffmpeg`, and `python3` with `numpy`. Run this from the repository root:

```bash
landing/reel/render.sh            # ~15 min, ~2 GB in landing/reel/build (gitignored)
PUBLISH=0 landing/reel/render.sh  # leave ../dist/assets untouched
```

`build/blindpass-reel-master.mp4` is the full-quality cut: CRF 14 with AAC at 256 kbps, about 128 MB. The published web cut is denoised and encoded at CRF 22, about 8 MB, because the film grain otherwise triples the bitrate. Each 60 fps frame averages two 120 fps renders, which gives the motion blur.

`frames.cjs` skips frames that already exist and recycles the browser every 400 frames. `render.sh` relaunches it on a crash or a 10-minute stall. Long single-browser sessions died or hung partway through. Delete `build/frames` after changing `reel.html`, or stale frames are reused.

## Coupling to the landing page

The reel lands two match cuts on pixels in `build/page2x.jpg`. The first shrinks its diagram onto the hero's exchange diagram. The second flattens the camera onto the closing section's heading. The numbers for both are hard-coded in `reel.html`:

- `G` holds the section rectangles that lift off the page in 3D.
- The scene-3 layout is scaled 1.934× from the hero diagram, around orbit center (1062.8, 442.8).
- The match-cut transform is `scale 0.6894` with offsets `457.1, 120.4`.
- The closing text starts at (132.05, 477.9).

`capture.cjs` removes the "In motion" section before measuring. That keeps the page matching the layout these numbers came from, and stops the reel from containing itself. If the page layout changes, compare `build/geom.json` against those constants and update them before re-rendering. The 2026-09-26 capture matched every recorded rectangle.

## Content rules

The reel follows the same claim discipline as the page (see [../README.md](../README.md)). It shows only the implemented agent-to-agent exchange (request, exchange-policy check, fulfiller-encrypted handoff decrypted by the requester runtime) and this page's own content. Do not add the proposed host broker, browser session handoff, or fleet work as if it were available.
