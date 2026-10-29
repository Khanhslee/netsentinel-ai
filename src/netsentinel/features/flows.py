"""Generic flow helpers: grouping and inter-arrival statistics."""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Callable, Hashable, Iterable, List, Tuple

from ..models import Flow


def group_by(flows: Iterable[Flow], key_fn: Callable[[Flow], Hashable]):
    """Group flows by a computed key, preserving first-seen insertion order."""
    groups: "defaultdict" = defaultdict(list)
    order: List[Hashable] = []
    for f in flows:
        k = key_fn(f)
        if k not in groups:
            order.append(k)
        groups[k].append(f)
    return [(k, groups[k]) for k in order]


def interarrival_stats(times: List[float]) -> Tuple[float, float, float]:
    """Return (mean, std_dev, count) of inter-arrival gaps for a sorted time list."""
    times = sorted(t for t in times if t > 0)
    if len(times) < 2:
        return 0.0, 0.0, max(0, len(times) - 1)
    intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    mean = sum(intervals) / len(intervals)
    var = sum((d - mean) ** 2 for d in intervals) / len(intervals)
    return mean, math.sqrt(var), len(intervals)


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of a string."""
    if not text:
        return 0.0
    counts: "defaultdict" = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    total = len(text)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def second_level_domain(fqdn: str) -> str:
    """Return the last two labels of a domain ('a.b.example.com' -> 'example.com')."""
    labels = [l for l in fqdn.rstrip(".").split(".") if l]
    if len(labels) <= 1:
        return labels[0] if labels else ""
    return ".".join(labels[-2:])


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Division that never raises and never returns infinity/NaN."""
    try:
        if not denominator:
            return default
        return float(numerator) / float(denominator)
    except (TypeError, ValueError, ZeroDivisionError):
        return default


def coefficient_of_variation(mean: float, std: float) -> float:
    """Coefficient of variation (sigma / mu) - the beacon jitter metric."""
    return round(safe_div(std, mean), 4)


def entropy_profile(values: Iterable[str]) -> dict:
    """Summarise Shannon entropy across a set of strings (forensic evidence)."""
    scores = [shannon_entropy(v) for v in values if v]
    if not scores:
        return {"count": 0, "min": 0.0, "max": 0.0, "avg": 0.0}
    return {
        "count": len(scores),
        "min": round(min(scores), 3),
        "max": round(max(scores), 3),
        "avg": round(sum(scores) / len(scores), 3),
    }


def label_length_stats(names: Iterable[str]) -> dict:
    """Longest / average DNS label length across a set of FQDNs."""
    lengths = [max((len(lbl) for lbl in n.split(".")), default=0) for n in names if n]
    if not lengths:
        return {"max": 0, "avg": 0.0}
    return {"max": max(lengths), "avg": round(sum(lengths) / len(lengths), 2)}


def throughput(n_bytes: int, seconds: float) -> float:
    """Bytes per second, guarding against zero/negative durations."""
    return round(safe_div(n_bytes, max(seconds, 1e-6)), 2)
