#!/usr/bin/env python3
"""
Reads timing_results.csv produced by attacker.py and saves a bar chart
(timing_chart.png) showing the staircase pattern of winner response times
across recovered positions.
"""

import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # no GUI — file output only
import matplotlib.pyplot as plt


CSV_PATH = "timing_results.csv"
PNG_PATH = "timing_chart.png"


def _load(path: str) -> dict[int, dict[str, list[float]]]:
    """Parse *path* into a nested dict keyed by position → char → [ms, …].

    Returns:
        Mapping of position → {candidate_char: [response_ms, ...]}.
    """
    data: dict[int, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            pos  = int(row["position"])
            char = row["candidate_char"]
            ms   = float(row["response_ms"])
            data[pos][char].append(ms)
    return data


def _percentile(values: list[float], p: float) -> float:
    """Linear-interpolation percentile (mirrors attacker.py)."""
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    lo = int(k)
    frac = k - lo
    if frac == 0 or lo + 1 >= len(s):
        return s[lo]
    return s[lo] + frac * (s[lo + 1] - s[lo])


def _winners(data: dict[int, dict[str, list[float]]]) -> list[tuple[int, str, float, float]]:
    """For each position return (pos, winner_char, mean_ms, p10_ms).

    The winner is the candidate with the highest p10 — the same criterion the
    attacker used — so this chart replays the attack's decision at each step.
    """
    rows = []
    for pos in sorted(data):
        chars = data[pos]
        ranked = sorted(chars.items(), key=lambda kv: _percentile(kv[1], 10), reverse=True)
        winner_char, winner_times = ranked[0]
        rows.append((pos, winner_char, statistics.mean(winner_times), _percentile(winner_times, 10)))
    return rows


def plot(winners: list[tuple[int, str, float, float]], out: str) -> None:
    """Render and save the staircase bar chart to *out*.

    Args:
        winners: rows from ``_winners()``.
        out:     output PNG path.
    """
    positions  = [r[0] for r in winners]
    chars      = [r[1] for r in winners]
    means      = [r[2] for r in winners]
    p10s       = [r[3] for r in winners]

    fig, ax = plt.subplots(figsize=(10, 5))

    bars = ax.bar(positions, means, color="#4c72b0", zorder=2, label="mean RTT (winner)")
    ax.plot(positions, p10s, "o--", color="#dd8452", linewidth=1.5,
            markersize=6, zorder=3, label="p10 RTT (winner)")

    # Annotate each bar with the recovered character
    for bar, char, mean_val in zip(bars, chars, means):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            mean_val + 0.4,
            f"'{char}'",
            ha="center", va="bottom", fontsize=11, fontweight="bold", color="#2c2c2c",
        )

    ax.set_xticks(positions)
    ax.set_xticklabels([f"pos {p}" for p in positions], fontsize=10)
    ax.set_ylabel("Response time (ms)", fontsize=11)
    ax.set_title(
        "Timing side-channel: winner RTT per recovered position\n"
        "Each position adds ~5 ms — the staircase is the leak",
        fontsize=12,
    )
    ax.legend(fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.5, zorder=0)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f"[*] Chart saved to {out}  ({len(positions)} positions, {len(winners)} bars)")


def main() -> None:
    """Load CSV, derive winners, plot staircase chart, save PNG."""
    if not Path(CSV_PATH).exists():
        raise SystemExit(f"[!] {CSV_PATH} not found — run attacker.py first.")
    data    = _load(CSV_PATH)
    winners = _winners(data)
    plot(winners, PNG_PATH)


if __name__ == "__main__":
    main()
