"""Flow-metadata ingestion: NetFlow-ish CSV/JSON and Zeek conn.log -> Flow objects."""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..models import Flow

_ALIASES = {
    "src_ip": "src_ip", "src": "src_ip", "saddr": "src_ip",
    "id.orig_h": "src_ip", "srcip": "src_ip",
    "dst_ip": "dst_ip", "dst": "dst_ip", "daddr": "dst_ip",
    "id.resp_h": "dst_ip", "dstip": "dst_ip",
    "src_port": "src_port", "sport": "src_port",
    "id.orig_p": "src_port", "srcport": "src_port",
    "dst_port": "dst_port", "dport": "dst_port",
    "id.resp_p": "dst_port", "dstport": "dst_port",
    "proto": "proto", "protocol": "proto",
    "src_bytes": "src_bytes", "orig_bytes": "src_bytes", "sent_bytes": "src_bytes",
    "dst_bytes": "dst_bytes", "resp_bytes": "dst_bytes", "recv_bytes": "dst_bytes",
    "src_packets": "src_packets", "orig_pkts": "src_packets",
    "dst_packets": "dst_packets", "resp_pkts": "dst_packets",
    "start_time": "start_time", "ts": "start_time",
    "end_time": "end_time", "duration": "duration",
    "tcp_flags": "tcp_flags", "flags": "tcp_flags",
    "dns_qname": "dns_qname", "query": "dns_qname",
    "dns_qtype": "dns_qtype", "qtype_name": "dns_qtype",
    "dns_rcode": "dns_rcode", "rcode": "dns_rcode",
    "dns_is_query": "dns_is_query",
}


def _norm(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for raw_k, raw_v in row.items():
        k = str(raw_k).strip().rstrip(".")
        canonical = _ALIASES.get(k)
        if canonical:
            out[canonical] = raw_v
    return out


def _i(v, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return default


def _f(v, default: float = 0.0) -> float:
    try:
        number = float(v)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def flows_from_dicts(rows: Iterable[Dict[str, Any]]) -> List[Flow]:
    flows: List[Flow] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        r = _norm(raw)
        if "src_ip" not in r or "dst_ip" not in r:
            continue
        flows.append(
            Flow(
                src_ip=str(r["src_ip"]),
                dst_ip=str(r["dst_ip"]),
                src_port=_i(r.get("src_port")),
                dst_port=_i(r.get("dst_port")),
                proto=str(r.get("proto", "tcp")).lower(),
                src_bytes=_i(r.get("src_bytes")),
                dst_bytes=_i(r.get("dst_bytes")),
                src_packets=_i(r.get("src_packets")),
                dst_packets=_i(r.get("dst_packets")),
                start_time=_f(r.get("start_time")),
                end_time=_f(r.get("end_time"), _f(r.get("start_time")) + _f(r.get("duration"))),
                tcp_flags=str(r.get("tcp_flags", "")),
                dns_qname=str(r["dns_qname"]).rstrip(".") if r.get("dns_qname") else None,
                dns_qtype=str(r["dns_qtype"]).upper() if r.get("dns_qtype") else None,
                dns_rcode=_i(r.get("dns_rcode")) if "dns_rcode" in r else None,
                dns_is_query=(str(r["dns_is_query"]).lower() in ("true", "1", "yes"))
                if "dns_is_query" in r else (_i(r.get("src_port")) != 53 if r.get("dns_qname") else None),
            )
        )
    return flows


def parse_json(path) -> List[Flow]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("flows", data.get("records", []))
    if not isinstance(data, list):
        raise ValueError("Flow JSON must be an array or an object containing a flows/records array")
    return flows_from_dicts(data)


def parse_csv(path) -> List[Flow]:
    with open(path, newline="", encoding="utf-8") as fh:
        return flows_from_dicts(csv.DictReader(fh))


_ZEEK_DEFAULT_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts",
    "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


def parse_zeek_conn(path) -> List[Flow]:
    fields: List[str] = []
    rows: List[Dict[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.rstrip("\n")
            if s.startswith("#fields"):
                fields = s.split("\t")[1:]
            elif s.startswith("#") or not s.strip():
                continue
            else:
                values = s.split("\t")
                if fields and len(values) >= len(fields):
                    rows.append(dict(zip(fields, values)))
    if not fields:
        fields = _ZEEK_DEFAULT_FIELDS
        rows = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                values = line.rstrip("\n").split("\t")
                if len(values) >= len(fields):
                    rows.append(dict(zip(fields, values)))
    return flows_from_dicts(rows)
