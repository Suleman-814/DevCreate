#!/usr/bin/env python3
# ids_gui.py - GUI-based Network Intrusion Detection System

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import time
import queue
import yaml
from datetime import datetime
import os
import sys

# Import your IDS modules
from capture import live_capture, pcap_capture
from flow import FlowTable
from signature import SignatureEngine
from anomaly import load_model, score_flow
from alert import AlertSink, make_alert

class IDSGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Initialize variables
        self.is_running = False
        self.capture_thread = None
        self.config = None
        self.alert_queue = queue.Queue()
        self.stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'alerts_generated': 0,
            'anomalies_detected': 0,
            'signatures_triggered': 0
        }
        
        # IDS Components
        self.flow_table = None
        self.signature_engine = None
        self.anomaly_model = None
        self.alert_sink = None
        
        self.create_widgets()
        self.load_default_config()
        
        # Start GUI update loop
        self.update_gui()
    
    def create_widgets(self):
        # Create main frame with modern styling
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        
        # Title
        title_label = ttk.Label(main_frame, text="🛡️ Network Intrusion Detection System", 
                               style='Header.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Control Panel Tab
        self.create_control_tab(notebook)
        
        # Alerts Tab
        self.create_alerts_tab(notebook)
        
        # Statistics Tab
        self.create_stats_tab(notebook)
        
        # Configuration Tab
        self.create_config_tab(notebook)
        
        # Status bar at bottom
        self.create_status_bar(main_frame)
    
    def create_control_tab(self, notebook):
        control_frame = ttk.Frame(notebook)
        notebook.add(control_frame, text="🎮 Control Panel")
        
        # Control buttons frame
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(pady=20)
        
        # Start/Stop button
        self.start_button = ttk.Button(button_frame, text="▶️ Start IDS", 
                                      command=self.toggle_ids, width=15)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Load Config button
        load_config_btn = ttk.Button(button_frame, text="📁 Load Config", 
                                    command=self.load_config_file, width=15)
        load_config_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear Alerts button
        clear_alerts_btn = ttk.Button(button_frame, text="🗑️ Clear Alerts", 
                                     command=self.clear_alerts, width=15)
        clear_alerts_btn.pack(side=tk.LEFT, padx=5)
        
        # Export Alerts button
        export_btn = ttk.Button(button_frame, text="💾 Export Alerts", 
                               command=self.export_alerts, width=15)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Current configuration display
        config_frame = ttk.LabelFrame(control_frame, text="Current Configuration")
        config_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.config_text = scrolledtext.ScrolledText(config_frame, height=15, width=80)
        self.config_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Real-time log
        log_frame = ttk.LabelFrame(control_frame, text="System Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_alerts_tab(self, notebook):
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text="🚨 Live Alerts")
        
        # Alert filter frame
        filter_frame = ttk.Frame(alerts_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter by severity:").pack(side=tk.LEFT, padx=5)
        
        self.severity_filter = ttk.Combobox(filter_frame, values=["All", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], 
                                           state="readonly", width=10)
        self.severity_filter.set("All")
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        filter_btn = ttk.Button(filter_frame, text="Apply Filter", command=self.apply_alert_filter)
        filter_btn.pack(side=tk.LEFT, padx=5)
        
        # Alerts tree view
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Severity', 'Type', 'Description')
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=120)
        
        # Scrollbars for alerts tree
        alerts_scroll_v = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        alerts_scroll_h = ttk.Scrollbar(alerts_frame, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=alerts_scroll_v.set, xscrollcommand=alerts_scroll_h.set)
        
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        alerts_scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        alerts_scroll_h.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Alert details
        details_frame = ttk.LabelFrame(alerts_frame, text="Alert Details")
        details_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.alert_details = scrolledtext.ScrolledText(details_frame, height=8)
        self.alert_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind selection event
        self.alerts_tree.bind('<<TreeviewSelect>>', self.on_alert_select)
    
    def create_stats_tab(self, notebook):
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Statistics")
        
        # Statistics display
        stats_main_frame = ttk.Frame(stats_frame)
        stats_main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Real-time stats
        realtime_frame = ttk.LabelFrame(stats_main_frame, text="Real-time Statistics")
        realtime_frame.pack(fill=tk.X, pady=10)
        
        stats_grid_frame = ttk.Frame(realtime_frame)
        stats_grid_frame.pack(padx=10, pady=10)
        
        # Create statistics labels
        self.stats_labels = {}
        stats_items = [
            ('packets_processed', 'Packets Processed'),
            ('flows_analyzed', 'Flows Analyzed'),
            ('alerts_generated', 'Total Alerts'),
            ('anomalies_detected', 'Anomalies Detected'),
            ('signatures_triggered', 'Signatures Triggered')
        ]
        
        for i, (key, label) in enumerate(stats_items):
            row, col = i // 2, (i % 2) * 2
            
            ttk.Label(stats_grid_frame, text=f"{label}:").grid(row=row, column=col, sticky=tk.W, padx=5, pady=5)
            self.stats_labels[key] = ttk.Label(stats_grid_frame, text="0", font=('Arial', 12, 'bold'))
            self.stats_labels[key].grid(row=row, column=col+1, sticky=tk.W, padx=5, pady=5)
        
        # Runtime stats
        runtime_frame = ttk.LabelFrame(stats_main_frame, text="Runtime Information")
        runtime_frame.pack(fill=tk.X, pady=10)
        
        runtime_grid = ttk.Frame(runtime_frame)
        runtime_grid.pack(padx=10, pady=10)
        
        ttk.Label(runtime_grid, text="System Status:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.status_label = ttk.Label(runtime_grid, text="Stopped", font=('Arial', 12, 'bold'), foreground='red')
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(runtime_grid, text="Uptime:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.uptime_label = ttk.Label(runtime_grid, text="00:00:00")
        self.uptime_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Alert rate chart (simplified text-based)
        chart_frame = ttk.LabelFrame(stats_main_frame, text="Recent Activity")
        chart_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.activity_text = scrolledtext.ScrolledText(chart_frame, height=12)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_config_tab(self, notebook):
        config_frame = ttk.Frame(notebook)
        notebook.add(config_frame, text="⚙️ Configuration")
        
        # Configuration editor
        ttk.Label(config_frame, text="Edit configuration and click 'Apply' to update settings", 
                 style='Header.TLabel').pack(pady=10)
        
        config_editor_frame = ttk.Frame(config_frame)
        config_editor_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.config_editor = scrolledtext.ScrolledText(config_editor_frame, height=25)
        self.config_editor.pack(fill=tk.BOTH, expand=True)
        
        # Config buttons
        config_btn_frame = ttk.Frame(config_frame)
        config_btn_frame.pack(pady=10)
        
        apply_config_btn = ttk.Button(config_btn_frame, text="✅ Apply Configuration", 
                                     command=self.apply_config)
        apply_config_btn.pack(side=tk.LEFT, padx=5)
        
        reset_config_btn = ttk.Button(config_btn_frame, text="🔄 Reset to Default", 
                                     command=self.reset_config)
        reset_config_btn.pack(side=tk.LEFT, padx=5)
        
        save_config_btn = ttk.Button(config_btn_frame, text="💾 Save to File", 
                                    command=self.save_config_file)
        save_config_btn.pack(side=tk.LEFT, padx=5)
    
    def create_status_bar(self, parent):
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_text = ttk.Label(status_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_text.pack(fill=tk.X, side=tk.LEFT)
        
        self.time_label = ttk.Label(status_frame, text="", relief=tk.SUNKEN)
        self.time_label.pack(side=tk.RIGHT)
    
    def load_default_config(self):
        """Load default configuration"""
        try:
            with open("config.yaml", "r") as f:
                self.config = yaml.safe_load(f)
            self.update_config_display()
            self.log_message("✅ Default configuration loaded")
        except Exception as e:
            self.config = self.get_default_config()
            self.log_message(f"⚠️ Using built-in config: {e}")
            self.update_config_display()
    
    def get_default_config(self):
        """Get built-in default configuration"""
        return {
            'capture': {
                'mode': 'live',
                'interface': 'Wi-Fi',
                'pcap_file': 'data/sample.pcap',
                'bpf': 'ip'
            },
            'flows': {
                'active_timeout_s': 30,
                'idle_timeout_s': 15,
                'export_interval_s': 2
            },
            'anomaly': {
                'model_path': 'models/rf_model.joblib',
                'contamination': 0.03
            },
            'alerts': {
                'out_file': 'alerts.jsonl',
                'min_severity_to_log': 3
            }
        }
    
    def update_config_display(self):
        """Update configuration display in GUI"""
        if self.config:
            config_str = yaml.dump(self.config, default_flow_style=False)
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, config_str)
            
            self.config_editor.delete(1.0, tk.END)
            self.config_editor.insert(1.0, config_str)
    
    def toggle_ids(self):
        """Start or stop the IDS"""
        if self.is_running:
            self.stop_ids()
        else:
            self.start_ids()
    
    def start_ids(self):
        """Start the IDS in a separate thread"""
        try:
            # Initialize IDS components
            self.flow_table = FlowTable(
                active_timeout_s=self.config["flows"]["active_timeout_s"],
                idle_timeout_s=self.config["flows"]["idle_timeout_s"]
            )
            
            # Load signature engine
            rules_path = self.config.get("rules_path", "rules.yaml")
            self.signature_engine = SignatureEngine(rules_path)
            
            # Load anomaly model
            self.anomaly_model = load_model(self.config["anomaly"]["model_path"])
            
            # Initialize alert sink
            self.alert_sink = AlertSink(
                self.config["alerts"]["out_file"], 
                self.config["alerts"]["min_severity_to_log"]
            )
            
            # Start capture thread
            self.is_running = True
            self.start_time = time.time()
            self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
            self.capture_thread.start()
            
            # Update UI
            self.start_button.configure(text="⏹️ Stop IDS")
            self.status_label.configure(text="Running", foreground='green')
            self.update_status("🚀 IDS Started Successfully")
            self.log_message("🚀 IDS started successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start IDS: {str(e)}")
            self.log_message(f"❌ Failed to start IDS: {e}")
    
    def stop_ids(self):
        """Stop the IDS"""
        self.is_running = False
        
        # Update UI
        self.start_button.configure(text="▶️ Start IDS")
        self.status_label.configure(text="Stopped", foreground='red')
        self.update_status("⏹️ IDS Stopped")
        self.log_message("⏹️ IDS stopped")
    
    def capture_loop(self):
        """Main capture loop running in separate thread"""
        try:
            def on_packet(pkt):
                if not self.is_running:
                    return
                
                self.stats['packets_processed'] += 1
                
                # Process packet through flow table
                exported = self.flow_table.update(pkt)
                
                for (key, flow) in exported:
                    self.stats['flows_analyzed'] += 1
                    
                    # Extract payload sample
                    payload_sample = ""
                    try:
                        payload_sample = bytes(pkt.payload.payload)[:256].decode("latin1", errors="ignore")
                    except Exception:
                        pass
                    
                    # Check signatures
                    hits = self.signature_engine.eval_flow(flow, payload_sample)
                    if hits:
                        self.stats['signatures_triggered'] += 1
                    
                    # Check for port scanning
                    unique_ports = self.flow_table.current_unique_ports(flow["src"], flow["dst"], window=10)
                    if unique_ports >= 20:
                        hits.append({
                            "rule_id": "R1002",
                            "name": "Suspicious Port Scan",
                            "severity": 6,
                            "description": "Many ports in short window"
                        })
                    
                    # Check anomaly
                    try:
                        anom = score_flow(self.anomaly_model, flow)
                        if anom > 1.0:
                            self.stats['anomalies_detected'] += 1
                    except Exception:
                        anom = 0.0
                    
                    # Generate alert if needed
                    if hits or anom > 1.0:
                        alert = make_alert(flow, hits, anom)
                        self.alert_sink.write(alert)
                        self.stats['alerts_generated'] += 1
                        
                        # Add to GUI queue
                        self.alert_queue.put(alert)
            
            # Start capture based on mode
            cap = self.config["capture"]
            if cap["mode"] == "live":
                self.log_message(f"📡 Starting live capture on {cap['interface']}")
                live_capture(cap["interface"], cap["bpf"], on_packet)
            else:
                self.log_message(f"📁 Reading PCAP file: {cap['pcap_file']}")
                pcap_capture(cap["pcap_file"], on_packet)
                
        except Exception as e:
            self.log_message(f"❌ Capture error: {e}")
            self.is_running = False
    
    def update_gui(self):
        """Update GUI elements periodically"""
        # Update time
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.configure(text=current_time)
        
        # Update uptime
        if self.is_running:
            uptime_seconds = int(time.time() - self.start_time)
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            self.uptime_label.configure(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # Update statistics
        for key, label in self.stats_labels.items():
            label.configure(text=str(self.stats[key]))
        
        # Process new alerts
        try:
            while not self.alert_queue.empty():
                alert = self.alert_queue.get_nowait()
                self.add_alert_to_tree(alert)
        except queue.Empty:
            pass
        
        # Schedule next update
        self.root.after(1000, self.update_gui)
    
    def add_alert_to_tree(self, alert):
        """Add alert to the alerts tree view"""
        timestamp = datetime.fromtimestamp(alert['ts']).strftime("%H:%M:%S")
        
        # Determine alert type
        alert_type = "Anomaly" if alert['anomaly_score'] > 1.0 else "Signature"
        if alert['signature_hits']:
            alert_type = alert['signature_hits'][0]['name']
        
        # Get description
        description = "High anomaly score"
        if alert['signature_hits']:
            description = alert['signature_hits'][0]['description']
        
        # Insert into tree
        item = self.alerts_tree.insert('', 0, values=(
            timestamp,
            alert['src'],
            alert['dst'], 
            alert['proto'],
            alert['severity'],
            alert_type,
            description
        ))
        
        # Color coding by severity
        if alert['severity'] >= 7:
            self.alerts_tree.set(item, 'Severity', f"🔴 {alert['severity']}")
        elif alert['severity'] >= 5:
            self.alerts_tree.set(item, 'Severity', f"🟡 {alert['severity']}")
        else:
            self.alerts_tree.set(item, 'Severity', f"🟢 {alert['severity']}")
        
        # Store full alert data
        self.alerts_tree.item(item, tags=(json.dumps(alert),))
        
        # Log activity
        activity_msg = f"[{timestamp}] {alert_type} - {alert['src']} → {alert['dst']} (Severity: {alert['severity']})\n"
        self.activity_text.insert(tk.END, activity_msg)
        self.activity_text.see(tk.END)
    
    def on_alert_select(self, event):
        """Handle alert selection in tree"""
        selection = self.alerts_tree.selection()
        if selection:
            item = selection[0]
            tags = self.alerts_tree.item(item, 'tags')
            if tags:
                try:
                    alert_data = json.loads(tags[0])
                    details = json.dumps(alert_data, indent=2)
                    self.alert_details.delete(1.0, tk.END)
                    self.alert_details.insert(1.0, details)
                except:
                    pass
    
    def apply_alert_filter(self):
        """Apply severity filter to alerts"""
        # This would filter the tree view based on severity
        pass
    
    def clear_alerts(self):
        """Clear all alerts from display"""
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        self.alert_details.delete(1.0, tk.END)
        self.activity_text.delete(1.0, tk.END)
        self.log_message("🗑️ Alerts cleared")
    
    def export_alerts(self):
        """Export alerts to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                alerts = []
                for child in self.alerts_tree.get_children():
                    tags = self.alerts_tree.item(child, 'tags')
                    if tags:
                        alerts.append(json.loads(tags[0]))
                
                with open(filename, 'w') as f:
                    json.dump(alerts, f, indent=2)
                
                messagebox.showinfo("Success", f"Exported {len(alerts)} alerts to {filename}")
                self.log_message(f"💾 Exported {len(alerts)} alerts to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export alerts: {str(e)}")
    
    def load_config_file(self):
        """Load configuration from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml"), ("YAML files", "*.yml"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.config = yaml.safe_load(f)
                self.update_config_display()
                self.log_message(f"📁 Configuration loaded from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {str(e)}")
    
    def apply_config(self):
        """Apply configuration from editor"""
        try:
            config_text = self.config_editor.get(1.0, tk.END)
            self.config = yaml.safe_load(config_text)
            self.update_config_display()
            self.log_message("✅ Configuration applied")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid configuration: {str(e)}")
    
    def reset_config(self):
        """Reset to default configuration"""
        self.config = self.get_default_config()
        self.update_config_display()
        self.log_message("🔄 Configuration reset to default")
    
    def save_config_file(self):
        """Save configuration to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        if filename:
            try:
                config_text = self.config_editor.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(config_text)
                messagebox.showinfo("Success", f"Configuration saved to {filename}")
                self.log_message(f"💾 Configuration saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {str(e)}")
    
    def log_message(self, message):
        """Add message to system log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_text.configure(text=message)

def main():
    """Main function to start the GUI"""
    # Check if model exists
    if not os.path.exists("models/rf_model.joblib"):
        print("❌ Model not found! Please train the model first:")
        print("   python train_ids.py")
        print("   python train_model.py")
        return
    
    root = tk.Tk()
    app = IDSGui(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n👋 IDS GUI shutting down...")

if __name__ == "__main__":
    main()