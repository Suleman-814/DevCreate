#signatures.py

import yaml 
from typing import Dict, Any, List

class SignatureEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, "r")as f:
            y = yaml.safe_load(f)
        self.rules = y.get("rules", [])

    def eval_flow(self, flow: Dict[str, Any], payload_sample: str = "")-> List[Dict]:
        hits = []
        for r in self.rules:
            cond = r.get("when", {})
            ok = True
            if "src_ip_in" in cond:
                ok = ok and flow["src"] in cond["src_ip_in"]
            if "payload_contains_any" in cond and payload_sample:
                low = payload_sample.lower()
                ok = ok and any(s in low for s in cond["payload_contains_any"])
            if "syn_ratio_over" in cond:
                if flow["packets"] >= cond.get("min_packets", 0):
                    ok = ok and flow["syn_ratio"] > cond["syn_ratio_over"]
            if "dst_ports_over_n_unique" in cond:
                pass  
            if ok:
                hits.append({
                    "rule_id": r["id"],
                    "name": r.get("name",""),
                    "severity": r.get("severity", 3),
                    "description": r.get("description","")
                })
        return hits