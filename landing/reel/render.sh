#!/usr/bin/env bash
# Renders the landing reel end to end and writes the published video and poster into ../dist/assets.
# Needs the workspace npm install (Playwright's Chromium), ffmpeg, and python3 with numpy.
# Takes ~15 minutes and ~2 GB in build/. Set PUBLISH=0 to leave ../dist/assets untouched.
set -euo pipefail
cd "$(dirname "$0")"
B=build
mkdir -p "$B/frames"

node capture.cjs

for attempt in $(seq 1 40); do
  rc=0
  timeout 600 node frames.cjs || rc=$?
  [ "$rc" -eq 0 ] && break
  echo "frame renderer exited ($rc); resuming, attempt $attempt"
done
count=$(find "$B/frames" -name 'f_*.png' | wc -l)
[ "$count" -eq 1800 ] || { echo "only $count of 1800 frames rendered" >&2; exit 1; }

python3 score.py
ffmpeg -loglevel error -y -f f32le -ar 48000 -ac 2 -i "$B/score.f32" \
  -af "loudnorm=I=-14:TP=-1.5:LRA=11" -ar 48000 "$B/score.wav"

# Master: each 60 fps frame averages two 120 fps renders, which is the motion blur.
ffmpeg -loglevel error -y -framerate 120 -i "$B/frames/f_%04d.png" -i "$B/score.wav" -map 0:v -map 1:a \
  -vf "tmix=frames=2:weights='1 1',fps=60,format=yuv420p" -c:v libx264 -preset slow -crf 14 -tune animation \
  -c:a aac -b:a 256k -shortest -movflags +faststart "$B/blindpass-reel-master.mp4"

# Web: the film grain would otherwise triple the bitrate, so denoise first; aq-mode 3 keeps the near-black panels.
ffmpeg -loglevel error -y -i "$B/blindpass-reel-master.mp4" -i "$B/score.wav" -map 0:v -map 1:a \
  -vf "hqdn3d=3:3:9:9" -c:v libx264 -preset slower -crf 22 -x264-params aq-mode=3:aq-strength=1.0 \
  -profile:v high -pix_fmt yuv420p -c:a aac -b:a 128k -movflags +faststart "$B/blindpass-reel.mp4"
# Poster: frame 474 (7.9 s), the policy check locking on ALLOW.
ffmpeg -loglevel error -y -i "$B/blindpass-reel-master.mp4" -vf "select=eq(n\,474),scale=1600:-1" \
  -frames:v 1 -q:v 4 "$B/reel-poster.jpg"

if [ "${PUBLISH:-1}" = 1 ]; then
  cp "$B/blindpass-reel.mp4" "$B/reel-poster.jpg" ../dist/assets/
  echo "published to ../dist/assets"
fi
