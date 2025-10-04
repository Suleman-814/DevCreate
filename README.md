Prerequisites
Python 3.7 or higher
Administrator/root privileges (for live packet capture)
Network interface access
1. Installation
# Install dependencies
pip install -r requirements.txt
2. Model Training
# Generate synthetic training data
python train_ids.py

# Train the anomaly detection model
python train_model.py
3. Choose Your Interface
🖥️ GUI Version (Recommended for beginners)
python ids_gui.py
⌨️ Command Line Version
# Live capture (requires admin privileges)
sudo python ids_main.py --config config.yaml

# PCAP file analysis
python ids_main.py --config config.yaml
