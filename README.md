# 🛡️ Network Intrusion Detection System (IDS)

A comprehensive Python-based network intrusion detection system that combines signature-based detection with machine learning anomaly detection using Isolation Forest. Features both command-line and GUI interfaces for maximum flexibility.

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)

## ✨ Features

### Core Detection Capabilities
- **Real-time packet capture** from network interfaces
- **PCAP file analysis** for offline forensic investigation
- **Flow-based analysis** with configurable timeouts
- **Signature-based detection** using flexible YAML rule definitions
- **Anomaly detection** using Isolation Forest machine learning
- **Multi-layered alerting** with severity-based filtering
- **JSON-formatted alerts** for easy integration with SIEM systems

### User Interfaces
- **🖥️ GUI Interface**: Modern tkinter-based graphical interface
- **⌨️ CLI Interface**: Command-line interface for automation and scripting
- **📊 Real-time Monitoring**: Live statistics and alert visualization
- **⚙️ Configuration Management**: Dynamic configuration editing

### Advanced Features
- **Port scan detection** with configurable thresholds
- **Payload analysis** with keyword matching
- **TCP flag analysis** for connection profiling
- **Anomaly scoring** with customizable sensitivity
- **Alert export** functionality for reporting

## 📁 Project Structure

```
network-ids/
├── 🎮 GUI Interface
│   ├── ids_gui.py              # Main GUI application
│   └── run_ids_gui.py          # GUI launcher with setup
├── ⌨️ CLI Interface  
│   └── ids_main.py             # Command-line interface
├── 🔧 Core Components
│   ├── capture.py              # Packet capture functionality
│   ├── flow.py                 # Network flow analysis
│   ├── signature.py            # Signature-based detection
│   ├── anomaly.py              # ML anomaly detection
│   └── alert.py                # Alert generation and logging
├── 🤖 Machine Learning
│   ├── train_ids.py            # Training data generation
│   ├── train_model.py          # Model training script
│   ├── test_model.py           # Model testing utility
│   └── evaluate_model.py       # Model evaluation metrics
├── ⚙️ Configuration
│   ├── config.yaml             # System configuration
│   └── rules.yaml              # Detection rules
├── 📊 Data & Models
│   ├── models/                 # Trained ML models
│   │   └── iso_forest.joblib
│   └── data/                   # Sample data files
└── 📚 Documentation
    ├── README.md               # This file
    ├── LICENSE                 # License information
    └── requirements.txt        # Python dependencies
```

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (for live packet capture)
- Network interface access

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-ids.git
cd network-ids

# Install dependencies
pip install -r requirements.txt
```

### 2. Model Training

```bash
# Generate synthetic training data
python train_ids.py

# Train the anomaly detection model
python train_model.py
```

### 3. Choose Your Interface

#### 🖥️ GUI Version (Recommended for beginners)
```bash
python ids_gui.py
```

#### ⌨️ Command Line Version
```bash
# Live capture (requires admin privileges)
sudo python ids_main.py --config config.yaml

# PCAP file analysis
python ids_main.py --config config.yaml
```

## 🖥️ GUI Interface

### Main Features

#### 🎮 Control Panel
- **Start/Stop Controls**: One-click IDS activation
- **Configuration Loading**: Dynamic config file management
- **System Logs**: Real-time operation monitoring
- **Alert Management**: Clear and export functionality

#### 🚨 Live Alerts
- **Real-time Display**: Immediate alert visualization
- **Severity Filtering**: Focus on critical threats
- **Detailed Analysis**: Complete alert information
- **Color Coding**: Visual severity indicators

#### 📊 Statistics Dashboard
- **Live Metrics**: Packets, flows, and alert counts
- **Runtime Information**: System status and uptime
- **Activity Timeline**: Recent detection events
- **Performance Monitoring**: System resource usage

#### ⚙️ Configuration Editor
- **Live Editing**: Modify settings without restart
- **Syntax Validation**: YAML configuration checking
- **Template Management**: Save and load configurations
- **Default Reset**: Quick configuration recovery

### GUI Screenshots

| Control Panel | Live Alerts | Statistics |
|:-------------:|:-----------:|:----------:|
| ![Control](docs/images/control-panel.png) | ![Alerts](docs/images/live-alerts.png) | ![Stats](docs/images/statistics.png) |

## ⚙️ Configuration

### System Configuration (config.yaml)

```yaml
capture:
  mode: "live"                    # "live" or "pcap"
  interface: "Wi-Fi"              # Network interface name
  pcap_file: "data/sample.pcap"   # PCAP file for offline analysis
  bpf: "ip"                       # Berkeley Packet Filter

flows:
  active_timeout_s: 30            # Active flow timeout
  idle_timeout_s: 15              # Idle flow timeout  
  export_interval_s: 2            # Flow export interval

anomaly:
  model_path: "models/iso_forest.joblib"
  contamination: 0.03             # Expected anomaly rate (3%)
  train_epochs: 1

alerts:
  out_file: "alerts.jsonl"        # Alert output file
  min_severity_to_log: 3          # Minimum severity threshold
```

### Detection Rules (rules.yaml)

```yaml
rules:
  - id: R1001
    name: "Blocklisted IP"
    when:
      src_ip_in: ["malicious.ip.1", "malicious.ip.2"]
    severity: 7
    description: "Traffic from known bad IP"
    
  - id: R1003  
    name: "SQL Injection Attempt"
    when:
      payload_contains_any: ["select ", "union ", "or 1=1"]
    severity: 5
    description: "Potential SQL injection in payload"
```

#### Supported Rule Conditions
| Condition | Description | Example |
|-----------|-------------|---------|
| `src_ip_in` | Source IP blocklist | `["1.2.3.4", "5.6.7.8"]` |
| `payload_contains_any` | Payload keyword detection | `["wget", "curl", "nc"]` |
| `syn_ratio_over` | High SYN ratio threshold | `0.8` |
| `dst_ports_over_n_unique` | Port scan detection | `20` |

## 🤖 Machine Learning

### Flow Features
The system analyzes network flows using these key features:

| Feature | Description | Detection Use |
|---------|-------------|---------------|
| packets | Total packet count | Volume anomalies |
| bytes | Total byte count | Data transfer patterns |
| duration | Flow duration (seconds) | Connection timing |
| pps | Packets per second | Traffic intensity |
| bps | Bytes per second | Bandwidth utilization |
| mean_iat | Mean inter-arrival time | Timing patterns |
| var_iat | Variance of inter-arrival times | Traffic regularity |
| syn_ratio | Ratio of SYN packets | Connection establishment |
| ack_ratio | Ratio of ACK packets | Connection reliability |
| payload_bytes | Total payload bytes | Data content volume |

### Model Training

```bash
# Generate diverse training data
python train_ids.py

# Train with custom parameters
python train_model.py --contamination 0.05 --epochs 1

# Evaluate model performance
python evaluate_model.py models/iso_forest.joblib synthetic_dataset.csv
```

### Model Evaluation Metrics
- **Precision**: Accuracy of anomaly predictions
- **Recall**: Coverage of actual anomalies
- **F1-Score**: Balanced precision and recall
- **ROC-AUC**: Overall classification performance

## 📊 Alert Format

Alerts are generated in structured JSON format:

```json
{
  "ts": 1634567890.123,
  "src": "192.168.1.100",
  "dst": "10.0.0.1", 
  "sport": 12345,
  "dport": 80,
  "proto": "TCP",
  "features": {
    "packets": 156,
    "bytes": 87543,
    "duration": 45.2,
    "pps": 3.45,
    "bps": 1937.4,
    "syn_ratio": 0.02,
    "ack_ratio": 0.87
  },
  "signature_hits": [
    {
      "rule_id": "R1003",
      "name": "SQL Injection Attempt",
      "severity": 5,
      "description": "Potential SQL injection in payload"
    }
  ],
  "anomaly_score": 2.34,
  "severity": 7
}
```

## 🧪 Testing & Validation

### Unit Tests
```bash
# Test individual components
python -m pytest tests/

# Test with coverage
python -m pytest tests/ --cov=. --cov-report=html
```

### Model Validation
```bash
# Test trained model
python test_model.py

# Comprehensive evaluation
python evaluate_model.py models/iso_forest.joblib test_data.csv
```

### Sample Data
```bash
# Generate test PCAP files
python generate_test_data.py

# Validate detection rules
python test_signatures.py
```

## 🔧 Advanced Usage

### Custom Rule Development

1. **Edit rules.yaml**:
```yaml
- id: R2001
  name: "Custom Detection Rule"
  when:
    payload_contains_any: ["custom_pattern"]
  severity: 6
  description: "Custom threat detection"
```

2. **Extend signature.py** for complex conditions:
```python
def eval_custom_condition(self, flow, condition):
    # Implement custom detection logic
    return detection_result
```

### Integration with SIEM

```python
# Forward alerts to external systems
import requests

def send_to_siem(alert):
    requests.post('https://siem-endpoint.com/alerts', 
                  json=alert, 
                  headers={'Authorization': 'Bearer token'})
```

### Performance Tuning

```yaml
# High-traffic networks
flows:
  active_timeout_s: 60
  idle_timeout_s: 30
  
# Memory optimization  
capture:
  bpf: "tcp and port 80"  # Filter relevant traffic
```

## 🚨 Troubleshooting

### Common Issues

#### Permission Denied (Live Capture)
```bash
# Linux/macOS
sudo python ids_gui.py
sudo python ids_main.py

# Windows (Run as Administrator)
python ids_gui.py
```

#### Model Not Found
```bash
# Train the model first
python train_ids.py
python train_model.py

# Verify model exists
ls -la models/iso_forest.joblib
```

#### No Network Traffic Detected
- Check network interface name in config.yaml
- Verify BPF filter syntax
- Test with PCAP file first

#### High False Positive Rate
```yaml
# Adjust anomaly sensitivity
anomaly:
  contamination: 0.05  # Increase for fewer false positives

# Raise minimum severity
alerts:
  min_severity_to_log: 5
```

### Performance Optimization

| Issue | Solution |
|-------|----------|
| High Memory Usage | Reduce flow timeouts, use BPF filters |
| CPU Overload | Lower capture rate, optimize rules |
| Slow Detection | Train model with more data, tune thresholds |
| False Positives | Collect more training data, adjust contamination |

## 🔒 Security Considerations

- **Network Access**: Requires promiscuous mode for full monitoring
- **Data Privacy**: Packet capture may contain sensitive information
- **Resource Usage**: Monitor system resources during high-traffic periods
- **Model Security**: Protect trained models from unauthorized access

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/network-ids.git

# Create development environment
python -m venv ids-dev
source ids-dev/bin/activate  # Linux/macOS
# ids-dev\Scripts\activate   # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest
```

### Contribution Areas
- 🐛 Bug fixes and improvements
- 📊 New detection algorithms
- 🎨 GUI enhancements
- 📚 Documentation updates
- 🧪 Test coverage expansion
- 🚀 Performance optimizations

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[Scapy](https://scapy.net/)** - Powerful packet manipulation library
- **[scikit-learn](https://scikit-learn.org/)** - Machine learning toolkit
- **[NumPy](https://numpy.org/)** & **[Pandas](https://pandas.pydata.org/)** - Data processing
- **[PyYAML](https://pyyaml.org/)** - Configuration management
- Network security research community for detection techniques

## 📞 Support & Contact

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/network-ids/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/yourusername/network-ids/discussions)
- 📧 **Security Issues**: security@yourproject.com
- 💬 **Community**: [Discord Server](https://discord.gg/yourproject)

## 📈 Roadmap

### Version 2.0 (Upcoming)
- [ ] **Deep Learning Models**: LSTM-based sequence analysis
- [ ] **Distributed Detection**: Multi-node deployment
- [ ] **REST API**: RESTful interface for integration
- [ ] **Advanced Visualization**: Interactive network graphs
- [ ] **Cloud Integration**: AWS/Azure deployment support

### Version 2.1 (Future)
- [ ] **Real-time Dashboards**: Web-based monitoring
- [ ] **Threat Intelligence**: IOC feed integration
- [ ] **Automated Response**: Blocking and mitigation
- [ ] **Mobile Alerts**: Push notifications
- [ ] **Forensic Analysis**: Deep packet inspection

---

**Made with ❤️ for Network Security**

*Star ⭐ this repository if you find it useful!*
