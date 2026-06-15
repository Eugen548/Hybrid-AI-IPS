# Hybrid-AI-IPS

## Overview

Hybrid-AI-IPS is an experimental AI-assisted intrusion prevention framework that combines machine learning-based attack detection with kernel-level packet filtering. The framework integrates a Random Forest (RF) classifier, an LSTM network for temporal behaviour analysis, SHAP-based explainability, and eBPF/XDP enforcement mechanisms.

The implementation was developed as part of doctoral research focused on enhancing intrusion prevention systems through hybrid AI-driven log analysis and predictive blocking techniques.

## Architecture

The framework consists of the following components:

### Source Code

* **ai_controller.py** – event trigger and orchestration component.
* **extractor.py** – feature extraction and preprocessing module responsible for constructing the fixed-length feature vector expected by the AI models.
* **ai_engine.py** – machine-learning inference engine integrating RF, LSTM, hybrid scoring, and SHAP explainability.
* **ai_server.py** – management and enforcement server responsible for maintaining the blacklist and interacting with the pinned eBPF map.
* **metrics_collector.py** – resource monitoring component used to collect CPU, memory, and network statistics during experiments.
* **unban_trigger.py** – auxiliary component responsible for synchronizing unban actions with the AI management server and the eBPF/XDP blacklist.
* **train_rf.py** – Random Forest training pipeline.
* **train_lstm.py** – LSTM training pipeline.

### Enforcement Layer

* **xdp_block.c** – eBPF/XDP program used for kernel-level packet filtering and packet dropping.

### Machine Learning Models

* **rf_model.pkl** – trained Random Forest model.
* **lstm_model.h5** – trained LSTM model.
* **scaler.pkl** – feature scaler used during training and inference.
* **features.pkl** – feature ordering metadata required for inference consistency.

## Dataset

The machine-learning models were trained using the CICIDS2017 dataset:

> I. Sharafaldin, A. Habibi Lashkari, and A. A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018.

The dataset is not redistributed in this repository and must be obtained separately from the original source.

## Requirements

### Tested Environment

* Ubuntu 24.04 LTS
* Linux Kernel 6.x
* Python 3.12
* Fail2Ban 1.0.2
* eBPF/XDP support enabled

### Install Dependencies

```bash
pip install -r requirements.txt
```
## Training the Models

### Random Forest

```bash
python3 source_code/train_rf.py
```

### LSTM

```bash
python3 source_code/train_lstm.py
```

## Running the Framework

### Start the AI Inference Engine

```bash
python3 source_code/ai_engine.py
```

### Start the Management Server

```bash
python3 source_code/ai_server.py
```

### Trigger an Event

```bash
python3 source_code/ai_controller.py --ban <IP_ADDRESS>
```

## Repository Structure


Hybrid-AI-IPS/
│
├── README.md
├── LICENSE
├── CITATION.cff
├── requirements.txt
├── REPRODUCIBILITY.md
│
├── source_code/
│   ├── ai_controller.py
│   ├── ai_engine.py
│   ├── ai_server.py
│   ├── extractor.py
│   ├── train_rf.py
│   └── train_lstm.py
│
├── models/
│   ├── rf_model.pkl
│   ├── lstm_model.h5
│   ├── scaler.pkl
│   └── features.pkl
│
├── ebpf/
│   └── xdp_block.c
│
└── artifacts/
    ├── ai_ips/
    │   ├── benign/
    │   ├── brute_force/
    │   ├── slow_brute_force/
    │   └── port_scan/
    │
    └── fail2ban/
        ├── benign/
        ├── brute_force/
        ├── slow_brute_force/
        └── port_scan/

## Experimental Artifacts

To support reproducibility, the repository includes raw experimental artefacts for both the proposed AI-IPS framework and the Fail2Ban baseline.

### AI-IPS Artifacts

For each experimental scenario:

* metrics.csv
* events_pull.jsonl
* kernel_blocked.jsonl
* blacklist_meta.json

### Fail2Ban Artifacts

For each experimental scenario:

* auth.log
* fail2ban.log
* metrics.csv

### Evaluated Scenarios

* Benign traffic
* SSH brute-force attack
* Slow SSH brute-force attack
* Port scanning

The provided artefacts contain decision traces, resource-monitoring measurements, kernel-level enforcement records, and baseline logs used during the evaluation reported in the associated publication.

## Reproducibility

The repository includes:

* source code;
* trained model files and metadata;
* eBPF/XDP enforcement code;
* experimental artefacts;
* monitoring datasets;
* baseline comparison logs.

Detailed reproduction information is provided in **REPRODUCIBILITY.md**.

## Limitations

The current implementation was evaluated in a controlled virtualized environment and focuses primarily on SSH brute-force attack mitigation. The framework should be considered a research prototype rather than a production-ready intrusion prevention system.

The implementation was designed as a proof-of-concept platform for studying the integration of machine learning, explainable AI, and kernel-level enforcement mechanisms within intrusion prevention systems.

## License

This repository is provided for research and educational purposes.
