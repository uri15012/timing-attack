# Timing Side-Channel Attack — Portfolio Demo

A self-contained demonstration of a **remote timing side-channel attack** against
a mock authentication server.  All traffic stays on localhost; nothing here is
intended for use against real systems.

---

## What is a timing side-channel attack?

A timing side-channel attack exploits the fact that a program's execution time
can depend on the *value* of secret data, not just its length.  In a naïve
password comparison that walks characters left-to-right and returns immediately
on the first mismatch, a candidate that matches the first *k* characters takes
longer to reject than one that mismatches at character 0.  The attacker does not
need to see inside the server — the clock on the network connection leaks the
information instead.

The attack works position by position.  To recover character *i*, hold the first
*i−1* characters fixed (already recovered), then sweep all 36 candidates
(a–z, 0–9) for position *i*, sending each candidate several times and recording
round-trip latency.  The candidate whose **low-percentile response time is
highest** matched one more character than all the others and slept one extra
`CHAR_DELAY` interval inside the server.  Lock it in and move to position *i+1*.

Network jitter is the main adversary.  A single probe can be dominated by OS
scheduling noise, so each candidate is probed *N* times and the **10th
percentile** is used as the representative latency.  Percentile selection and the
calibration step (described below) make the technique robust even when jitter is
several milliseconds.

---

## Architecture

```
 attacker.py                                   server.py
 ───────────                                   ─────────
 calibrate()
   send 30 baseline probes  ───────────────►  compare_password("xxxxxxxx")
   measure RTT stdev                            no match at char 0 → return immediately
   choose N (5–25 samples)  ◄───────────────  FAIL\n  (~0.1 ms)

 attack(): position 0
   ThreadPoolExecutor(8)
   for ch in "abcde…z0…9":
     probe N times           ───────────────►  compare_password("fxxxxxxx")
                                                'f'=='f' → sleep 5 ms
                                                'x'!='3' → return
                             ◄───────────────  FAIL\n  (~5 ms)  ← timing leak

     probe N times           ───────────────►  compare_password("axxxxxxx")
                                                'a'!='f' → return immediately
                             ◄───────────────  FAIL\n  (~0.1 ms)

   pick char with max p10                      ← 'f' wins by ~5 ms delta
   lock in 'f', move to pos 1

 attack(): position 1
   for ch in CHARSET:
     probe "f" + ch + filler ───────────────►  compare_password("f3xxxxxx")
                                                'f'=='f' → sleep 5 ms
                                                '3'=='3' → sleep 5 ms
                                                'x'!='a' → return
                             ◄───────────────  FAIL\n  (~10 ms)
   ...

 after position 7:
   send "admin:f3a9k2z1"     ───────────────►  compare_password("f3a9k2z1")
                                                all 8 chars match → return True
                             ◄───────────────  OK\n   ← confirmed
```

---

## How to run

**Requirements:** Python 3.10+, `matplotlib` (`pip install matplotlib`)

```bash
# Terminal 1 — start the vulnerable server
python3 server.py

# Terminal 2 — run the attacker
python3 attacker.py

# After attacker.py finishes it writes timing_results.csv.
# Generate the timing chart:
python3 visualize.py
# → saves timing_chart.png
```

**Expected attacker output:**

```
Timing side-channel attacker  →  127.0.0.1:9999

[*] Calibrating noise floor …
    Baseline RTT  mean=0.09 ms   stdev=0.05 ms
    Chosen N      5 samples per candidate

Pos  Char    p10(ms)   Delta(ms)  Runner-up   Known so far
──────────────────────────────────────────────────────────
[+] Position 0 → 'f'  p10=6.3 ms  delta=6.0 ms  runner-up='z'  known='f'
[+] Position 1 → '3'  p10=11.0 ms  delta=4.6 ms  runner-up='l'  known='f3'
...
[+] Position 7 → '1'  p10=47.4 ms  delta=3.2 ms  runner-up='i'  known='f3a9k2z1'

[*] Server confirmed OK — password recovered after 8 chars.

[=] Recovered password : 'f3a9k2z1'
[=] Total time         : 4.8 s
```

---

## Complexity reduction

| Approach | Attempts required |
|---|---|
| Brute force | 36⁸ = **2,821,109,907,456** |
| Timing attack | 36 × 8 = **288** (× N samples) |

The timing attack reduces the search space from ~2.8 trillion to 288 candidate
probes — a **~9.8 billion× reduction** — because each recovered character is
independent: once position *i* is locked in, it never needs to be revisited.
The complexity is O(|charset| × |password|) instead of O(|charset|^|password|).

---

## Why p10 instead of mean or median?

RTT distributions under load are **right-skewed**: the floor is set by the
server's processing time, but occasional OS scheduling pauses, TCP retransmits,
or context switches spike a small fraction of samples upward.  The *mean* and
*median* both absorb these spikes and pull the representative value away from the
true processing floor.

The **10th percentile** selects samples from the clean left tail — the ones where
no scheduling noise fired — giving a stable estimate of the server's actual
compute time.  This means a wrong candidate can never "look fast" because of
lucky samples on the correct candidate, and the correct candidate wins even with
N as small as 5.

On a noisy WAN you would raise the percentile toward p25 or p50 and increase N;
on a local socket (as here) p10 with N=5 is sufficient.

---

## Files

| File | Purpose |
|---|---|
| `server.py` | Intentionally vulnerable mock auth server |
| `probe.py` | Phase 2 sanity check — confirms the timing signal is detectable |
| `attacker.py` | Phase 3 character-by-character password recovery |
| `visualize.py` | Plots the staircase timing chart from `timing_results.csv` |
| `timing_results.csv` | Raw per-probe latency data written by `attacker.py` |
| `timing_chart.png` | Output chart written by `visualize.py` |
