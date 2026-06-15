Hybrid-AI-IPS

Overview

Hybrid-AI-IPS is an experimental intrusion prevention framework that combines machine learning-based attack detection with kernel-level packet filtering. The framework integrates a Random Forest classifier, an LSTM network for temporal analysis, SHAP-based explainability, and eBPF/XDP enforcement.
The implementation was developed as part of a doctoral research project focused on AI-assisted intrusion prevention systems.

Architecture

The framework consists of the following components:
•	ai_controller.py – event trigger and orchestration component.
•	extractor.py – feature preparation module responsible for building the fixed-length feature vector expected by the AI models.
•	ai_engine.py – machine learning inference engine integrating Random Forest, LSTM, and SHAP explainability.
•	ai_server.py – management and enforcement server responsible for maintaining the blacklist and interacting with the pinned eBPF map.
•	monitor_feedback.py – adaptive threshold monitoring component.
•	train_rf.py – Random Forest training pipeline.
•	train_lstm.py – LSTM training pipeline.
•	xdp_block.c – eBPF/XDP program used for kernel-level packet filtering.

Dataset

The machine learning models were trained using the CICIDS2017 dataset.
Dataset reference:
I. Sharafaldin, A. Habibi Lashkari, and A. A. Ghorbani,
"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
ICISSP 2018.
The dataset is not redistributed in this repository and must be obtained separately.

Requirements

Tested environment:
•	Ubuntu 24.04 LTS
•	Linux Kernel 6.x
•	Python 3.12
•	eBPF/XDP support enabled
Install dependencies:
pip install -r requirements.txt

Model Training

Random Forest:
python3 train_rf.py
LSTM:
python3 train_lstm.py

Running the Framework

Start the AI inference engine:
python3 ai_engine.py
Start the management server:
python3 ai_server.py
Trigger an event:
python3 ai_controller.py --ban <IP_ADDRESS>

Repository Structure

├── ai_controller.py
├── ai_engine.py
├── ai_server.py
├── extractor.py
├── train_rf.py
├── train_lstm.py
├── xdp_block.c
├── rf_model.pkl
├── lstm_model.h5
├── scaler.pkl
├── features.pkl
├── requirements.txt
├── README.md
├── CITATION.cff
└── LICENSE

Notes on Reproducibility

The repository contains the implementation used for the experimental proof-of-concept evaluation described in the associated publication.
Some deployment-specific paths, network settings, and runtime configuration parameters may require adaptation to the target environment.
For reproducibility purposes, the feature extraction module contains a simplified flow reconstruction example. In a production deployment, these values can be replaced by flow statistics collected through CICFlowMeter-compatible tools, tshark, conntrack, or equivalent monitoring mechanisms.
The feature order used during training is stored in:
features.pkl
and must remain unchanged during inference.

Limitations

The current implementation was evaluated in a controlled virtualized environment and focuses primarily on SSH brute-force attack mitigation.
The framework should be considered a research prototype rather than a production-ready intrusion prevention system.

License

This repository is provided for research and educational purposes.
