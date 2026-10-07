# P06 loaded timing bounds — 2026-10-06

**Status:** measured on the uncommitted tree above `8a595ad`, one host (16 logical CPUs, x86-64). It covers the two timing bounds in the P06 plan under synthetic host load. It is not a production capacity test and not a remote-controller or stock-client result. P06 acceptance remains false.

## Method

`tests/deployment/loaded-bounds.py` (new) forks 2x the logical CPUs of busy loops (32 on this host) and one `fsync`ing 256 MiB disk writer, waits 3 s, then runs a child command and kills the load afterwards. It prints host load average before and after. The children keep their own bounds: `compose-up.py` fails if controller readiness or Docker health exceeds 15 s; `p06-native-node-vm.py` fails if the unchanged node is not `online` within 120 s of the fence-to-serve sequence (`STATUS_BOUND_SECONDS`).

## Results

| Bound | Unloaded | Loaded (load1 28 to 40 on 16 CPUs) | Bound |
|---|---|---|---|
| Compose SQLite: activation to controller ready and healthy (`P06-O02/O03`) | 5.488 s | 5.722 s | 15 s |
| Compose PostgreSQL: same | 7.126 s | 6.319 s | 15 s |
| Compose SQLite: ready after SIGKILL plus fresh activation (`F1`) | 0.330 s | 0.876 s | 15 s |
| Compose PostgreSQL: same | 1.159 s | 1.360 s | 15 s |
| Native controller guest plus node guest: unchanged node online after activation (`S4`, Ubuntu 24.04) | 4.3 s | 63.5 s and 62.5 s (two runs) | 120 s |

Both loaded Compose runs and both loaded native runs exited 0 with every other PASS line of the harness (the Compose run includes the O01 layer scan, nginx and Caddy edges, upgrade, SIGKILL, 20 s suspend, database loss; the native run includes the full recovery sequence and stale-source refusals). Unloaded: `compose-up.py` for both profiles on the same image (`blindpass-p06-controller:node`), and the native `main` scenario once (the earlier record's 3.1 s runs are on an older archive).

## Reading the numbers

- Container startup is dominated by the Compose health-check interval and activation, not by CPU: load changed it by under 1 s.
- **Node reconnect is bounded by the node back-off, not by controller speed.** Under load the real node needed about 63 s instead of 4 s. `crates/blindpass-node/src/main.rs` retries a failed channel with a back-off that doubles from 1 s to a 60 s cap with 80% to 120% jitter (`next_backoff_seconds`, `jittered_backoff`). Loaded, the fence-to-serve sequence took about 95 s instead of 16 s, so the node had reached the capped back-off and slept up to 72 s before the next attempt; unloaded it was still on a short sleep. That fits both loaded runs landing within one second of each other. This is read from the code and the timings; I did not instrument the node to confirm it. The worst case for any outage longer than about a minute is therefore roughly 72 s plus the controller's ready time and one handshake, so the 120 s bound holds by design with headroom, but a longer back-off cap or a slower controller start would break it. Do not raise the cap without revisiting the bound.
- Load is synthetic and CPU/disk only: no memory pressure, network loss, many nodes, or browser traffic.

## Limits

- One node. Reconnect time with many nodes was not measured.
- Single host, one run per Compose cell, two loaded native runs and one unloaded native control.
- Debian 12 controller guest not run loaded.
- The load wrapper itself has no test; it only shapes host load (its effect is visible in the reported load average).

## Addendum: more loaded reconnect samples

The later [serving-faults runs](p06-serving-faults-2026-10-06.md) measured the same reconnect after the recovery activation under the same load: Ubuntu 23.0 s, 24.1 s and 28.1 s, Debian 3.9 s (fence-to-serve 66 s, 69 s, 71 s and 38 s). Together with the 62.5 s and 63.5 s above, loaded reconnect ranged from 3.9 s to 63.5 s and tracked the length of the outage, which supports the back-off explanation; none approached 120 s. The Debian controller guest has now also run loaded.
