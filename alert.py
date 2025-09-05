#alert.py

import json, time
from typing import List, Dict, Any

class AlertSink:
    def __init__(self, out_file:str, main_severity: int=3):
        self.out_file = out_file
        self.main_severity = main_severity

    def write(self, alert: Dict[str, Any]):
        if alert["severity"] < self.main_severity:
            return
        line = json.dumps(alert, ensure_ascii=False)
        print(line)
        with open(self.out_file, "a") as f:
            f.write(line + "\n")

def make_alert(flow: Dict[str,Any], hits: List[Dict], anomaly_score: float):
    severity = max([h["severity"] for h in hits], default=0)
    sev_anom = min(10, int(3 * anomaly_score))
    final_sev = max(severity, sev_anom)
    return {
        "ts": time.time(),
        "src": flow["src"], "dst": flow["dst"],
        "sport": flow["sport"], "dport": flow["dport"], "proto": flow["proto"],
        "features": {k: flow[k] for k in ["packets","bytes","duration","pps","bps","syn_ratio","ack_ratio"]},
        "signature_hits": hits,
        "anomaly_score": anomaly_score,
        "severity": final_sev
        }