#flow.py

import time, math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List
from scapy.layers.inet import IP, TCP, UDP

Flowkey = Tuple[str, str, int, int, str]

@dataclass
class Flowstats:
    first_ts: float = 0.0
    last_ts: float = 0.0
    packets: int = 0
    bytes: int = 0
    inter_arrivals: List[float] = field(default_factory=list)
    tcp_flags: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    payload_bytes: int = 0
    syns: int = 0
    acks: int = 0

def five_tuples(pkt) -> Optional[Flowkey]:
    if IP not in pkt: return None
    ip = pkt[IP]
    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else None)
    if proto is None: return None
    sport = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport)
    dport = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport)
    return (ip.src, ip.dst, sport, dport, proto)

class FlowTable:
    def __init__(self, active_timeout_s=30, idle_timeout_s=15):
        self.table: Dict[Flowkey, Flowstats] = {}
        self.active_timeout_s = active_timeout_s
        self.idle_timeout_s = idle_timeout_s
        self.port_touch: Dict[Tuple[str,str], deque] = defaultdict(deque)

    def update(self, pkt, ts=None):
        ts = ts or time.time()
        key = five_tuples(pkt)
        if not key: return []
        stats = self.table.get(key)
        if not stats:
            stats = Flowstats(first_ts=ts, last_ts=ts)
            self.table[key] = stats
        else:
            stats.inter_arrivals.append(ts - stats.last_ts)
            stats.last_ts = ts

        plen = int(len(pkt))
        stats.packets += 1
        stats.bytes += plen

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02: stats.syns += 1  # SYN
            if flags & 0x10: stats.acks += 1  # ACK
            
            for name, bit in [("SYN",0x02),("ACK",0x10),("FIN",0x01),("RST",0x04),("PSH",0x08),("URG",0x20)]:
                if flags & bit: stats.tcp_flags[name] += 1

        try:
            raw_payload = bytes(pkt.payload.payload)
            stats.payload_bytes += len(raw_payload)
        except Exception:
            pass

        (src, dst, sport, dport, proto) = key
        self.port_touch[(src, dst)].append((ts, dport))
        self._prune_port_touch((src, dst), window=10)

        return self._export_expired(ts)

    def _prune_port_touch(self, sd_key, window=10):
        dq = self.port_touch[sd_key]
        now = time.time()
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def _export_expired(self, now):
        exported = []
        to_del = []
        for key, st in self.table.items():
            if (now - st.first_ts) > self.active_timeout_s or (now - st.last_ts) > self.idle_timeout_s:
                exported.append((key, self.features(key, st)))
                to_del.append(key)
        for k in to_del:
            del self.table[k]
        return exported
    
    def features(self, key: Flowkey, st: Flowstats) -> Dict:
        duration = max(1e-6, st.last_ts - st.first_ts)
        iats = st.inter_arrivals or [duration]
        mean_iat = sum(iats)/len(iats)
        var_iat = (sum((x-mean_iat)**2 for x in iats)/len(iats)) if len(iats)>1 else 0.0
        syn_ratio = st.syns / max(1, st.packets)
        ack_ratio = st.acks / max(1, st.packets)
        return {
            "src": key[0], "dst": key[1],
            "sport": key[2], "dport": key[3], "proto": key[4],
            "packets": st.packets, "bytes": st.bytes, "duration": duration,
            "pps": st.packets/duration, "bps": st.bytes/duration,
            "mean_iat": mean_iat, "var_iat": var_iat,
            "syn_ratio": syn_ratio, "ack_ratio": ack_ratio,
            "payload_bytes": st.payload_bytes,
            "first_ts": st.first_ts, "last_ts": st.last_ts
        }
    
    def current_unique_ports(self, src, dst, window=10):
        dq = self.port_touch.get((src, dst), deque())
        recent = [p for (t,p) in dq if time.time() - t <= window]
        return len(set(recent))