# Reproducibility Guide

## Experimental Environment

The experiments reported in the accompanying publication were conducted in a controlled virtualized environment using:

* Ubuntu 24.04.4 LTS
* Linux Kernel 6.17
* Python 3.12.3
* Fail2Ban 1.0.2
* eBPF/XDP-based packet filtering

---

## Configuration Files

The configuration files used during the evaluation are provided in:

```text
configuration/
├── dynamic_config.json
└── fail2ban/
    ├── jail.local
    └── ai-ebpf-trigger.conf
```

These files contain:

* runtime threshold configuration;
* Fail2Ban jail settings;
* custom Fail2Ban trigger definitions used to integrate Fail2Ban with the AI-assisted workflow.

---

## Experimental Scenarios

The repository contains artifacts for the following evaluation scenarios:

### AI-IPS

* benign traffic
* SSH brute-force attack
* slow SSH brute-force attack
* port scanning

### Fail2Ban Baseline

* benign traffic
* SSH brute-force attack
* slow SSH brute-force attack
* port scanning

---

## Attack Commands

The commands used to generate the evaluation scenarios are documented in:

```text
ATTACK_SCENARIOS.md
```

This document includes:

* benign traffic generation procedures;
* SSH brute-force attack commands;
* slow brute-force attack commands;
* port-scanning commands;
* password-list generation procedures.

---

## Experimental Artifacts

### AI-IPS Artifacts

Each scenario directory contains:

#### metrics.csv

Resource-monitoring data including CPU and memory utilization.

#### events_pull.jsonl

AI-generated decision events collected during runtime.

#### kernel_blocked.jsonl

Kernel-level enforcement records associated with the XDP blacklist.

#### blacklist_meta.json

Decision metadata including:

* RF score;
* LSTM score;
* hybrid score;
* decision threshold;
* enforcement action.

---

### Fail2Ban Artifacts

Each scenario directory contains:

#### auth.log

Authentication events generated during the experiment.

#### fail2ban.log

Fail2Ban detection and banning events.

#### metrics.csv

Resource-monitoring measurements collected during execution.

---

## Reproduction Procedure

To reproduce the evaluation:

1. Install the required dependencies using `requirements.txt`.
2. Configure Fail2Ban using the provided configuration files.
3. Load the XDP/eBPF enforcement program.
4. Start the AI inference engine.
5. Start the management server.
6. Execute the desired scenario using the commands documented in `ATTACK_SCENARIOS.md`.
7. Collect the generated artifacts.
8. Compare the results with the reference artifacts included in the repository.

---

## Limitations

The implementation represents a research prototype intended for academic evaluation.

The experiments were conducted in a controlled virtualized environment and focus primarily on SSH brute-force mitigation. The framework was not evaluated as a production-ready intrusion prevention platform.

Certain environment-specific elements, such as virtual-machine provisioning, operating-system installation, network-topology recreation, and external dataset acquisition, must be recreated independently by researchers attempting to reproduce the evaluation.
