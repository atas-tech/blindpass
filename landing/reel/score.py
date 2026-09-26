"""Synthesized score for the BlindPass landing reel. Every cue is timed to reel.html."""
from pathlib import Path

import numpy as np

SR = 48000
DUR = 15.0
N = int(SR * DUR)
rng = np.random.default_rng(7)
BUS = {k: np.zeros((2, N)) for k in ("music", "drums", "fx", "sub")}


def tt(d):
    return np.arange(int(d * SR)) / SR


def place(sig, t0, g=1.0, pan=0.0, bus="fx"):
    i0 = int(round(t0 * SR))
    s = np.asarray(sig) * g
    if i0 < 0:
        s, i0 = s[-i0:], 0
    n = min(len(s), N - i0)
    if n <= 0:
        return
    s = s[:n]
    p = np.asarray(pan, dtype=float)
    p = p[:n] if p.ndim else p
    th = (np.clip(p, -1, 1) + 1) * np.pi / 4
    BUS[bus][0, i0:i0 + n] += s * np.cos(th) * np.sqrt(2)
    BUS[bus][1, i0:i0 + n] += s * np.sin(th) * np.sqrt(2)


def svf(x, fc, q=0.7, mode="band"):
    """Chamberlin state-variable filter with per-sample cutoff."""
    fc = np.broadcast_to(np.asarray(fc, dtype=float), x.shape)
    f = 2 * np.sin(np.pi * np.clip(fc, 20, SR / 6) / SR)
    low = band = 0.0
    out = np.empty_like(x)
    damp = 1 / q
    for i in range(len(x)):
        low += f[i] * band
        high = x[i] - low - damp * band
        band += f[i] * high
        out[i] = band if mode == "band" else low if mode == "low" else high
    return out


def saw(freq, d, k=24, roll=1600.0):
    t = tt(d)
    f = np.broadcast_to(np.asarray(freq, dtype=float), t.shape)
    ph = 2 * np.pi * np.cumsum(f) / SR
    out = np.zeros_like(t)
    for n in range(1, k + 1):
        amp = np.exp(-(n * f) / roll) / n
        out += amp * np.sin(n * ph) * (n * f < SR / 2.2)
    return out


def adsr(d, a=0.01, r=0.1):
    t = tt(d)
    return np.minimum(1, t / max(a, 1e-4)) * np.clip((d - t) / max(r, 1e-4), 0, 1)


# ---------- instruments ----------
def kick(g=1.0, t0=0.0):
    t = tt(0.55)
    f = 45 + 110 * np.exp(-t / 0.045)
    body = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / 0.22)
    click = rng.standard_normal(len(t)) * np.exp(-t / 0.002) * 0.35
    place(np.tanh(1.6 * (body + click)), t0, g, 0, "drums")


def boom(t0, g=1.0, d=2.2):
    t = tt(d)
    f = 26 + 60 * np.exp(-t / 0.25)
    s = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / 0.7)
    n = svf(rng.standard_normal(len(t)), 180, 0.8, "low") * np.exp(-t / 0.35) * 0.9
    place(np.tanh(1.3 * (s + n)), t0, g, 0, "sub")


def burst(t0, g=1.0, d=0.9):
    t = tt(d)
    n = rng.standard_normal((2, len(t)))
    for c in (0, 1):
        s = svf(n[c], 3200 * np.exp(-t / 0.4) + 400, 0.6, "low") * np.exp(-t / 0.18)
        place(s, t0, g, -0.7 if c == 0 else 0.7, "fx")


def clap(t0, g=1.0):
    t = tt(0.35)
    n = rng.standard_normal(len(t))
    env = sum(np.where(t >= o, np.exp(-(t - o) / 0.009), 0) for o in (0, 0.009, 0.018)) + 0.5 * np.exp(-t / 0.09)
    place(svf(n * env, 1500, 1.2), t0, g, 0.05, "drums")


def hat(t0, g=1.0, open_=False, pan=0.25):
    t = tt(0.25 if open_ else 0.06)
    n = rng.standard_normal(len(t))
    hp = np.diff(np.diff(n, prepend=0), prepend=0)
    place(hp * np.exp(-t / (0.07 if open_ else 0.014)) * 0.25, t0, g, pan, "drums")


def pluck(t0, f, g=1.0, pan=0.0, d=0.9, bright=2.5, bus="music"):
    t = tt(d)
    y = np.sin(2 * np.pi * f * t + bright * np.exp(-t / 0.07) * np.sin(2 * np.pi * 2 * f * t))
    y *= np.exp(-t / (d / 3.2)) * np.minimum(1, t / 0.002)
    place(y, t0, g, pan, bus)


def bell(t0, f, g=1.0, pan=0.0, d=1.6):
    t = tt(d)
    y = sum(a * np.sin(2 * np.pi * f * m * t) * np.exp(-t / (d / (2 + 2 * i)))
            for i, (m, a) in enumerate([(1, 1), (2.0, .45), (3.01, .25), (4.2, .18), (5.43, .08)]))
    place(y * np.minimum(1, t / 0.002), t0, g, pan, "fx")


def tick(t0, g=1.0, pan=0.0, f=None):
    t = tt(0.02)
    f = f or rng.uniform(2800, 6200)
    place(np.sin(2 * np.pi * f * t) * np.exp(-t / 0.0035), t0, g, pan, "fx")


def ticks(a, b, g=0.25, pan=0.0, rate=30):
    k = 0
    while a + k / rate < b:
        tick(a + k / rate + rng.uniform(0, 0.006), g * rng.uniform(0.6, 1), pan + rng.uniform(-.15, .15))
        k += 1


def whoosh(t0, d, f0, f1, g=1.0, pan0=0.0, pan1=0.0, shape=1.0, q=1.2):
    t = tt(d)
    x = t / d
    fc = f0 * (f1 / f0) ** x
    env = np.sin(np.pi * x ** shape) ** 2
    s = svf(rng.standard_normal(len(t)), fc, q) * env
    place(s, t0, g, pan0 + (pan1 - pan0) * x, "fx")


def riser(t0, d, f0, f1, g=1.0, noise=0.6):
    t = tt(d)
    x = t / d
    env = x ** 2.6 * np.minimum(1, (d - t) / 0.01)
    f = f0 * (f1 / f0) ** x
    tone = sum(saw(f * m, d, k=14, roll=900 + 3000 * x.mean()) for m in (1, 1.0035, 0.9965)) / 3
    n = svf(rng.standard_normal(len(t)), 300 * (40 ** x), 1.0) * noise
    place((tone + n) * env, t0, g, 0, "fx")


def zap(t0, d, f0, f1, g=1.0, pan=0.0):
    t = tt(d)
    f = f0 * (f1 / f0) ** (t / d)
    place(np.sin(2 * np.pi * np.cumsum(f) / SR) * np.sin(np.pi * t / d) ** 2, t0, g, pan, "fx")


def pad(t0, t1, notes, g=1.0, a=0.25, r=0.45, roll=1400.0):
    d = t1 - t0 + r
    t = tt(d)
    env = np.minimum(1, t / a) * np.clip((d - t) / r, 0, 1)
    for i, f in enumerate(notes):
        for j, det in enumerate((-0.006, 0, 0.006)):
            vib = f * (1 + det) * (1 + 0.0015 * np.sin(2 * np.pi * (4.3 + i * .37) * t + i))
            place(saw(vib, d, k=18, roll=roll) * env / len(notes), t0, g * 0.33, (j - 1) * 0.55, "music")


def bassline(t0, t1, notes, step=0.25, g=1.0, dec=0.18):
    k = 0
    while t0 + k * step < t1 - 0.02:
        f = notes[k % len(notes)]
        d = min(step * 0.95, t1 - (t0 + k * step))
        t = tt(d)
        env = np.exp(-t / dec) * np.minimum(1, t / 0.004) * np.clip((d - t) / 0.01, 0, 1)
        s = saw(f, d, k=12, roll=280 + 900 * np.exp(-t / 0.06)) + 0.6 * np.sin(2 * np.pi * f * t)
        place(np.tanh(1.4 * s) * env, t0 + k * step, g, 0, "sub")
        k += 1


def stream(a, b, g=0.3, pan0=0.6, pan1=-0.6):
    """Ciphertext crossing the frame: bit-crushed granular data."""
    k, rate = 0, 55
    while a + k / rate < b:
        x = k / ((b - a) * rate)
        t = tt(0.018)
        f = rng.choice([1320, 1760, 2640, 3520, 5280])
        sq = np.sign(np.sin(2 * np.pi * f * t)) * np.exp(-t / 0.006)
        place(sq * 0.3, a + k / rate, g * rng.uniform(.5, 1), pan0 + (pan1 - pan0) * x, "fx")
        k += 1


# ---------- notes ----------
NOTE = dict(D1=36.71, G1=49.0, A1=55.0, Bb1=58.27, C2=65.41, D2=73.42, G2=98.0, A2=110.0, Bb2=116.54,
            C3=130.81, D3=146.83, E3=164.81, F3=174.61, Fs3=185.0, G3=196.0, A3=220.0, Bb3=233.08,
            C4=261.63, Cs4=277.18, D4=293.66, E4=329.63, F4=349.23, Fs4=369.99, A4=440.0, D5=587.33,
            E5=659.26, F5=698.46, Fs5=739.99, A5=880.0, Cs6=1108.73, D6=1174.66, E6=1318.5, A6=1760.0)
n = lambda *k: [NOTE[x] for x in k]

# ---------- cue sheet (times match reel.html) ----------
kicks = []

# S1 — mark (0 – 2.3): drone, construction, tiles, shockwave, wordmark
pad(0.0, 2.2, n("D2", "A2", "D3"), g=0.55, a=1.2, r=0.4, roll=500)
whoosh(0.02, 0.8, 1200, 5200, g=0.05, pan0=-0.6, pan1=0.6, q=2.5)
pluck(0.15, NOTE["A5"], 0.2, 0, d=0.6, bright=1.2, bus="fx")
for i, f in enumerate(n("D5", "F5", "A5", "D6")):
    pluck(0.55 + i * 0.05, f, 0.26, (-0.45, 0.45, 0.45, -0.45)[i], d=1.3)
boom(1.0, 0.55, d=1.8)
whoosh(0.95, 0.7, 180, 900, g=0.12)
ticks(0.95, 1.4, g=0.08, pan=0.3)
whoosh(1.45, 0.55, 500, 2400, g=0.06, pan0=0.2, pan1=-0.3)
for j in range(9):
    tick(1.58 + j * 0.03, 0.1, -0.3 + j * 0.07, f=2200 + j * 180)
pluck(1.97, NOTE["D6"], 0.24, 0.35, d=0.7, bright=3.5, bus="fx")
riser(1.95, 0.35, 220, 880, g=0.18, noise=0.9)

# S2 — type (2.3 – 5.08): the drop
kick(1.1, 2.3); kicks.append(2.3)
burst(2.3, 0.22, d=0.6)
for k in range(1, 5):
    kick(0.9, 2.3 + 0.5 * k); kicks.append(2.3 + 0.5 * k)
for k in range(9):
    hat(2.55 + 0.25 * k, 0.8 if k % 2 == 0 else 0.45)
pad(2.3, 5.0, n("D3", "F3", "A3", "C4", "E4"), g=0.75, a=0.35, roll=1200)
bassline(2.3, 4.5, n("D2", "D2", "D3", "D2", "D2", "A1", "D2", "C2"), g=0.42)
ticks(2.55, 3.2, g=0.09, pan=0.0)
whoosh(3.06, 0.38, 700, 5000, g=0.1, pan0=-0.5, pan1=0.2, q=1.6)
for i, f in enumerate(n("D4", "F4", "A4", "D5", "E5")):
    pluck(3.42 + i * 0.012, f, 0.2, (i - 2) * 0.25, d=1.4, bright=3.0)
clap(3.42, 0.5)
whoosh(3.44, 0.36, 5000, 900, g=0.08, pan0=0.2, pan1=0.6, q=1.6)
for k in range(11):
    tick(3.76 + k * 0.045, 0.07, -0.5 + k * 0.1, f=1800 + 90 * k)
riser(4.45, 0.63, 110, 1320, g=0.5, noise=0.8)
zap(4.55, 0.53, 400, 3200, g=0.06)

# The flood (5.08): the biggest hit in the piece
kick(1.2, 5.08); kicks.append(5.08)
boom(5.08, 1.0, d=2.4)
burst(5.08, 0.45, d=1.2)
for i, f in enumerate(n("Bb2", "F3", "A3", "D4", "F4", "A4")):
    pluck(5.08, f, 0.16, (i - 2.5) * 0.3, d=2.0, bright=2.2)
zap(5.1, 0.55, 1400, 140, g=0.12)
whoosh(5.1, 0.55, 6000, 300, g=0.14, pan0=0, pan1=0, q=0.9)

# S3 — exchange (5.08 – 9.0): half-time, spatial
pad(5.08, 7.3, n("Bb2", "F3", "A3", "D4"), g=0.7, a=0.4)
pad(7.3, 9.0, n("C3", "G3", "D4", "E4"), g=0.7, a=0.25)
bassline(5.58, 7.3, n("Bb1", "Bb1", "F3", "Bb1"), step=0.25, g=0.3)
bassline(7.3, 8.95, n("C2", "C2", "G2", "C2"), step=0.25, g=0.3)
for k in range(1, 4):
    kick(0.85, 5.08 + k); kicks.append(5.08 + k)
    kick(0.5, 5.08 + k - 0.25); kicks.append(5.08 + k - 0.25)
for k in range(4):
    clap(5.58 + k, 0.45)
for k in range(15):
    hat(5.33 + 0.25 * k, 0.5 if k % 2 else 0.3, pan=0.35 * (-1) ** k)
pluck(5.52, NOTE["D4"], 0.3, 0, d=0.8, bright=1.5, bus="fx")
tick(5.82, 0.22, -0.4, f=2600); tick(5.84, 0.22, 0.4, f=3100)
whoosh(5.62, 0.55, 300, 2600, g=0.2, pan0=-1, pan1=-0.35, q=1.0)
whoosh(5.68, 0.55, 300, 2600, g=0.2, pan0=1, pan1=0.35, q=1.0)
zap(6.08, 0.42, 300, 900, g=0.05, pan=-0.5)
zap(6.13, 0.42, 300, 900, g=0.05, pan=0.5)
pluck(6.27, NOTE["A5"], 0.12, -0.7, d=0.4, bus="fx"); pluck(6.32, NOTE["A5"], 0.12, 0.7, d=0.4, bus="fx")
ticks(6.25, 6.9, g=0.08, pan=0.0)
ticks(6.62, 7.0, g=0.05, pan=-0.4)
t = tt(0.66)
carrier = np.sin(2 * np.pi * np.cumsum(880 * (1.5 ** (t / 0.66))) / SR) * (0.5 + 0.5 * np.sin(2 * np.pi * 16 * t)) * np.sin(np.pi * t / 0.66)
place(carrier, 6.6, 0.07, np.linspace(-0.65, 0, len(t)), "fx")
bell(7.25, NOTE["A5"], 0.18, 0); bell(7.26, NOTE["E6"], 0.1, 0.1)
ticks(7.22, 7.6, g=0.05, pan=0.0)
t = tt(0.77)
sweepn = svf(rng.standard_normal(len(t)), 900 + 2500 * np.sin(np.pi * t / 0.77), 3.0) * np.sin(np.pi * t / 0.77)
place(sweepn, 7.28, 0.1, 0.8 * np.sin(2 * np.pi * t / 0.35), "fx")
for tt0, f in ((7.3, NOTE["A4"]), (7.47, NOTE["Cs6"] / 2), (7.64, NOTE["E5"])):
    pluck(tt0, f, 0.16, 0, d=0.35, bright=1.0, bus="fx")
bell(7.8, NOTE["D6"], 0.2, -0.1); bell(7.84, NOTE["A6"], 0.12, 0.15)
pluck(7.8, NOTE["D5"], 0.15, 0, d=0.8, bus="fx")
zap(7.98, 0.2, 2400, 5200, g=0.07, pan=0.75)
stream(8.0, 8.78, g=0.22, pan0=0.7, pan1=-0.7)
ticks(7.98, 8.35, g=0.05, pan=0.5)
ticks(8.12, 8.72, g=0.04, pan=0.0)
for i, f in enumerate(n("D5", "F5", "A5", "D6", "F5", "A5")):
    pluck(8.78 + i * 0.035, f * (2 if i > 3 else 1), 0.13, -0.6 + i * 0.05, d=0.9, bright=2.0, bus="fx")
bell(8.8, NOTE["D6"], 0.1, -0.5)

# Match cut to the page (9.0 – 9.8)
whoosh(9.0, 0.66, 4200, 350, g=0.16, pan0=-0.2, pan1=0.35, q=1.0)
for i in range(8):
    whoosh(9.3 + i * 0.028, 0.22, 2500, 6000, g=0.03, pan0=-0.8, pan1=0.1)

# S4 — flyover (9.4 – 12.4): four on the floor
for k in range(6):
    kick(1.0 if k == 0 else 0.9, 9.4 + 0.5 * k); kicks.append(9.4 + 0.5 * k)
boom(9.4, 0.4, d=1.2)
for k in range(3):
    clap(9.9 + k, 0.5)
for k in range(6):
    hat(9.65 + 0.5 * k, 0.9, open_=True, pan=0.3)
    hat(9.525 + 0.5 * k, 0.35, pan=-0.3); hat(9.775 + 0.5 * k, 0.35, pan=-0.3)
pad(9.4, 10.9, n("D3", "A3", "F4", "A4"), g=0.75, a=0.12)
pad(10.9, 12.4, n("Bb2", "F3", "D4", "F4"), g=0.75, a=0.12)
bassline(9.4, 10.9, n("D2", "D3", "D2", "D3"), step=0.25, g=0.42)
bassline(10.9, 12.3, n("Bb1", "Bb2", "Bb1", "Bb2"), step=0.25, g=0.42)
t = tt(2.7)
fc = 350 + 2600 * np.exp(-((t - 1.3) / 0.7) ** 2)
air = svf(rng.standard_normal(len(t)), fc, 0.8) * (np.sin(np.pi * t / 2.7) ** 1.5)
place(air, 9.72, 0.16, -0.45 * np.sin(np.pi * t / 2.7), "fx")
for tt0, p in ((10.2, -0.6), (10.9, 0.5), (11.5, -0.4), (12.0, 0.4)):
    pluck(tt0, NOTE["A5"], 0.08, p, d=0.5, bright=1.5, bus="fx")

# S5 — close (12.4 – 15.0)
boom(12.4, 0.6, d=1.4)
kick(0.8, 12.4); kicks.append(12.4)
pad(12.4, 12.95, n("G2", "D3", "Bb3", "D4"), g=0.8, a=0.05)
pad(12.95, 13.42, n("A2", "E3", "A3", "Cs4", "E4"), g=0.9, a=0.08, r=0.08, roll=2200)
riser(12.5, 0.62, 146, 587, g=0.25, noise=0.5)
whoosh(13.08, 0.4, 900, 5200, g=0.14, pan0=-0.7, pan1=0.7, q=1.2)
zap(13.16, 0.32, 300, 3600, g=0.1)
riser(13.4, 0.28, 440, 2640, g=0.35, noise=1.0)

# Final resolve (13.68): minor → major, the mark rebuilds
kick(1.2, 13.68); kicks.append(13.68)
boom(13.68, 0.95, d=1.3)
burst(13.68, 0.35, d=1.1)
pad(13.68, 14.85, n("D2", "A2", "D3", "A3", "Fs4", "A4", "E5"), g=1.0, a=0.03, r=0.35, roll=1800)
for i, f in enumerate(n("D5", "Fs5", "A5", "D6")):
    pluck(13.68 + i * 0.031, f, 0.26, (-0.45, 0.45, 0.45, -0.45)[i], d=1.2)
boom(13.96, 0.3, d=1.0)
for j in range(9):
    tick(14.32 + j * 0.019, 0.09, -0.3 + j * 0.07, f=2400 + j * 200)
pluck(14.56, NOTE["D6"], 0.26, 0.35, d=0.44, bright=3.5, bus="fx")
bell(14.57, NOTE["A6"], 0.08, 0.3, d=0.43)
ticks(14.38, 14.82, g=0.07, pan=0.0)

# ---------- mix ----------
tl = np.arange(N) / SR
duck = np.ones(N)
for k in kicks:
    m = tl >= k
    duck[m] = np.minimum(duck[m], 1 - 0.55 * np.exp(-(tl[m] - k) / 0.13))
BUS["music"] *= duck
BUS["sub"] *= 0.35 + 0.65 * duck
# Suck-out before the final hit
gap = 1 - 0.95 * np.clip((tl - 13.42) / 0.12, 0, 1) * (tl < 13.68)
for b in BUS.values():
    b *= gap


def reverb(x, rt=2.2, seed=3):
    r = np.random.default_rng(seed)
    t = tt(rt)
    out = np.zeros_like(x)
    L = N + len(t)
    nfft = 1 << (L - 1).bit_length()
    for c in (0, 1):
        ir = r.standard_normal(len(t)) * np.exp(-t / (rt / 6.9)) * (1 - np.exp(-t / 0.008))
        IR = np.fft.rfft(ir, nfft)
        freqs = np.fft.rfftfreq(nfft, 1 / SR)
        IR *= 1 / (1 + (freqs / 5500) ** 2)
        out[c] = np.fft.irfft(np.fft.rfft(x[c], nfft) * IR, nfft)[:N]
    return out / np.max(np.abs(out) + 1e-9)


dry = BUS["music"] * 0.9 + BUS["drums"] * 1.0 + BUS["fx"] * 1.0 + BUS["sub"] * 0.9
send = BUS["music"] * 0.5 + BUS["fx"] * 0.6 + BUS["drums"] * 0.08
wet = reverb(send) * np.max(np.abs(send)) * 0.55
mix = dry + wet
mix -= mix.mean(axis=1, keepdims=True)
fade = np.minimum(1, tl / 0.01) * np.clip((DUR - tl) / 0.35, 0, 1)
mix *= fade
mix /= np.max(np.abs(mix))
mix = np.tanh(1.5 * mix) / np.tanh(1.5)
mix.T.astype(np.float32).tofile(Path(__file__).resolve().parent / "build" / "score.f32")
print("peak", float(np.max(np.abs(mix))), "samples", N)
