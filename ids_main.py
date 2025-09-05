#ids_main.py

import argparse, yaml, sys
from capture import live_capture, pcap_capture
from flow import FlowTable
from signature import SignatureEngine
from anomaly import load_model, score_flow
from alert import AlertSink, make_alert

def parse_args():
    ap = argparse.ArgumentParser(description = "Intrusion Detection System")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--train", action="store_true", help="(Handled via anomaly.py separately)")
    return ap.parse_args()

def load_cfg(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    args = parse_args()
    cfg = load_cfg(args.config)

    ft = FlowTable(
        active_timeout_s=cfg["flows"]["active_timeout_s"],
        idle_timeout_s=cfg["flows"]["idle_timeout_s"]
    )
    sig = SignatureEngine(cfg.get("rules_path","rules.yaml") or "rules.yaml")
    model = load_model(cfg["anomaly"]["model_path"])
    sink = AlertSink(cfg["alerts"]["out_file"], cfg["alerts"]["min_severity_to_log"])

    def on_packet(pkt):
        exported = ft.update(pkt)
        for (key, flow) in exported:
            payload_sample = ""
            try:
                payload_sample = bytes(pkt.payload.payload)[:256].decode("latin1", errors="ignore")
            except Exception:
                pass

            hits = sig.eval_flow(flow, payload_sample)
            unique_ports = ft.current_unique_ports(flow["src"], flow["dst"], window=10)
            if unique_ports >= 20:
                hits.append({"rule_id":"R1002","name":"Suspicious Port Scan","severity":6,"description":"Many ports in short window"})

            anom = score_flow(model, flow)
            if hits or anom > 1.0: 
                alert = make_alert(flow, hits, anom)
                sink.write(alert)

    cap = cfg["capture"]
    if cap["mode"] == "live":
        print(f"[*] Capturing on {cap['interface']} with BPF '{cap['bpf']}'")
        try:
            live_capture(cap["interface"], cap["bpf"], on_packet)
        except PermissionError:
            print("Run with sudo or grant capture capabilities.", file=sys.stderr)
    
    else:
        print(f"[*] Reading pcap {cap['pcap_file']}")
        pcap_capture(cap["pcap_file"], on_packet)

if __name__ == "__main__":
    main()