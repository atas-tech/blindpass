"use strict";

// The reel autoplays muted while in view. Sound restarts it so the score lands from the top.
const reelVideo = document.querySelector("#reel-video");
const reelFrame = document.querySelector(".reel-frame");
const reelPlay = document.querySelector("#reel-play");
const reelToggle = document.querySelector("#reel-toggle");
const reelSound = document.querySelector("#reel-sound");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
let reelHeld = false;

function syncReel() {
  reelFrame.classList.toggle("is-paused", reelVideo.paused);
  reelToggle.textContent = reelVideo.paused ? "Play" : "Pause";
  reelSound.setAttribute("aria-pressed", String(!reelVideo.muted));
}

function playReel() {
  const started = reelVideo.play();
  if (started && typeof started.catch === "function") started.catch(syncReel);
}

function toggleReel() {
  reelHeld = !reelVideo.paused;
  if (reelHeld) reelVideo.pause();
  else playReel();
}

reelPlay.addEventListener("click", toggleReel);
reelToggle.addEventListener("click", toggleReel);
reelVideo.addEventListener("click", toggleReel);
reelSound.addEventListener("click", () => {
  reelVideo.muted = !reelVideo.muted;
  if (!reelVideo.muted) {
    reelVideo.currentTime = 0;
    reelHeld = false;
    playReel();
  }
  syncReel();
});
["play", "pause", "volumechange"].forEach((name) => reelVideo.addEventListener(name, syncReel));

if ("IntersectionObserver" in window) {
  new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting && !reelHeld && !reduceMotion.matches) playReel();
      else if (!entry.isIntersecting && !reelVideo.paused) reelVideo.pause();
    });
  }, { threshold: 0.35 }).observe(reelFrame);
}
syncReel();
