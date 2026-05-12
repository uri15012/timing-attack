#!/usr/bin/env python3
"""
Phase 2 — timing sanity check.
Measures response latency for three known candidates to confirm
the server's timing leak is strong enough to build an attacker on.
"""

import socket
import time
import statistics

HOST = "127.0.0.1"
PORT = 9999
SAMPLES = 20

CANDIDATES = [
    ("wrongpass",  "admin:wrongpass"),   # 0 matching chars
    ("f3xxxxxxx",  "admin:f3xxxxxxx"),   # 2 matching chars
    ("f3a9k2z1",   "admin:f3a9k2z1"),    # 8 matching chars (full)
]


def probe(payload: str) -> float:
    """Send one login attempt and return round-trip time in milliseconds."""
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        start = time.perf_counter()
        s.sendall((payload + "\n").encode())
        s.recv(16)
        return (time.perf_counter() - start) * 1000


def percentile(data: list[float], p: float) -> float:
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    lo, frac = int(k), k % 1
    if frac == 0:
        return sorted_data[lo]
    return sorted_data[lo] + frac * (sorted_data[lo + 1] - sorted_data[lo])


def main() -> None:
    print(f"Probing {HOST}:{PORT} — {SAMPLES} samples per candidate\n")

    col_w = max(len(label) for label, _ in CANDIDATES) + 2
    header = f"{'Candidate':<{col_w}} | {'min(ms)':>8} | {'max(ms)':>8} | {'mean(ms)':>9} | {'p10(ms)':>8}"
    print(header)
    print("-" * len(header))

    for label, payload in CANDIDATES:
        times: list[float] = []
        for _ in range(SAMPLES):
            times.append(probe(payload))

        mn   = min(times)
        mx   = max(times)
        mean = statistics.mean(times)
        p10  = percentile(times, 10)

        print(f"{label:<{col_w}} | {mn:>8.2f} | {mx:>8.2f} | {mean:>9.2f} | {p10:>8.2f}")


if __name__ == "__main__":
    main()
