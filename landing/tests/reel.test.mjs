import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("../dist/reel.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");

// DOM doubles for the reel player; these do not exercise real media playback or layout.
function element() {
  const listeners = new Map();
  const attributes = new Map();
  const classes = new Set();
  return {
    textContent: "",
    classList: {
      toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
      contains: (name) => classes.has(name)
    },
    setAttribute(name, value) { attributes.set(name, value); },
    getAttribute(name) { return attributes.get(name); },
    addEventListener(name, callback) { listeners.set(name, [...(listeners.get(name) || []), callback]); },
    fire(name) { (listeners.get(name) || []).forEach((callback) => callback()); },
    click() { this.fire("click"); }
  };
}

function setup({ reduce = false, rejectPlay = false } = {}) {
  const video = Object.assign(element(), {
    paused: true, muted: true, currentTime: 0, plays: 0,
    play() {
      this.plays += 1;
      if (rejectPlay) return Promise.reject(new Error("NotAllowedError"));
      this.paused = false; this.fire("play"); return Promise.resolve();
    },
    pause() { this.paused = true; this.fire("pause"); }
  });
  const nodes = { "#reel-video": video, ".reel-frame": element(), "#reel-play": element(), "#reel-toggle": element(), "#reel-sound": element() };
  let observe;
  runInNewContext(script, {
    document: { querySelector(selector) { assert.ok(nodes[selector], `Missing selector ${selector}`); return nodes[selector]; } },
    window: {
      matchMedia: () => ({ matches: reduce }),
      IntersectionObserver: class { constructor(callback) { observe = callback; } observe() {} }
    },
    IntersectionObserver: class { constructor(callback) { observe = callback; } observe() {} }
  });
  return {
    video, nodes,
    view: (isIntersecting) => observe([{ isIntersecting }]),
    paused: () => nodes[".reel-frame"].classList.contains("is-paused"),
    sound: () => nodes["#reel-sound"].getAttribute("aria-pressed")
  };
}

test("reel markup references the selectors, assets and script the player needs", () => {
  for (const id of ["reel-video", "reel-play", "reel-toggle", "reel-sound", "reel-caption"]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /class="reel-frame[^"]*"/);
  assert.match(html, /<video[^>]*\bmuted\b[^>]*\bplaysinline\b/);
  assert.match(html, /preload="none"/);
  assert.match(html, /src="assets\/blindpass-reel\.mp4"/);
  assert.match(html, /poster="assets\/reel-poster\.jpg"/);
  assert.match(html, /<script src="reel\.js" defer><\/script>/);
});

test("autoplays muted in view, pauses out of view, and resumes", () => {
  const reel = setup();
  assert.equal(reel.paused(), true);
  assert.equal(reel.sound(), "false");
  reel.view(true);
  assert.equal(reel.video.paused, false);
  assert.equal(reel.video.muted, true);
  assert.equal(reel.paused(), false);
  assert.equal(reel.nodes["#reel-toggle"].textContent, "Pause");
  reel.view(false);
  assert.equal(reel.video.paused, true);
  reel.view(true);
  assert.equal(reel.video.paused, false);
});

test("a viewer's pause holds when the reel scrolls back into view", () => {
  const reel = setup();
  reel.view(true);
  reel.nodes["#reel-toggle"].click();
  assert.equal(reel.video.paused, true);
  reel.view(false);
  reel.view(true);
  assert.equal(reel.video.paused, true);
  reel.nodes["#reel-play"].click();
  assert.equal(reel.video.paused, false);
});

test("sound restarts the reel from the top; muting again does not", () => {
  const reel = setup();
  reel.view(true);
  reel.video.currentTime = 9.4;
  reel.nodes["#reel-sound"].click();
  assert.equal(reel.video.muted, false);
  assert.equal(reel.video.currentTime, 0);
  assert.equal(reel.sound(), "true");
  reel.video.currentTime = 4;
  reel.nodes["#reel-sound"].click();
  assert.equal(reel.video.muted, true);
  assert.equal(reel.video.currentTime, 4);
  assert.equal(reel.sound(), "false");
});

test("reduced motion never autoplays but still plays on request", () => {
  const reel = setup({ reduce: true });
  reel.view(true);
  assert.equal(reel.video.plays, 0);
  assert.equal(reel.paused(), true);
  reel.nodes["#reel-play"].click();
  assert.equal(reel.video.paused, false);
});

test("a blocked autoplay leaves the paused state and play control showing", async () => {
  const reel = setup({ rejectPlay: true });
  reel.view(true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(reel.video.plays, 1);
  assert.equal(reel.paused(), true);
  assert.equal(reel.nodes["#reel-toggle"].textContent, "Play");
});
