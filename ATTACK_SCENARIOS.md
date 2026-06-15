# Attack Scenarios

## Overview

This document describes the commands used to generate the experimental scenarios reported in the manuscript.

---

# Benign Traffic Scenario

## AI-IPS Host

```bash
TARGET=172.32.32.7
USER=cyber1

while [ $SECONDS -lt $END ]; do
    ssh ${USER}@${TARGET} "echo ok"
    ping -c 2 ${TARGET}
    scp /etc/hosts ${USER}@${TARGET}:/tmp/hosts_test
    sleep 2
done
```

## Fail2Ban Baseline Host

```bash
TARGET=172.32.32.8
USER=cyber2

while [ $SECONDS -lt $END ]; do
    ssh ${USER}@${TARGET} "echo ok"
    ping -c 2 ${TARGET}
    scp /etc/hosts ${USER}@${TARGET}:/tmp/hosts_test
    sleep 2
done
```

---

# SSH Brute-Force Scenario

## AI-IPS

```bash
TARGET=172.32.32.7
hydra -l fakeuser -P test_passwords_big.txt -t 4 ssh://$TARGET
```

## Fail2Ban Baseline

```bash
TARGET=172.32.32.8
hydra -l fakeuser -P test_passwords_big.txt -t 4 ssh://$TARGET
```

---

# Slow SSH Brute-Force Scenario

## AI-IPS

```bash
timeout 600 hydra -l root -P test_passwords_big.txt -t 1 -W 5 ssh://172.32.32.7
```

## Fail2Ban Baseline

```bash
timeout 600 hydra -l root -P test_passwords_big.txt -t 1 -W 5 ssh://172.32.32.8
```

---

# Port-Scanning Scenario

## AI-IPS

```bash
sudo nmap -sS -p- -T4 172.32.32.7
```

## Fail2Ban Baseline

```bash
sudo nmap -sS -p- -T4 172.32.32.8
```

---

# Password Dataset Used During Evaluation

```bash
seq 1 200 > test_passwords_big.txt
```

The objective of the brute-force experiments was to generate repeated authentication failures required for IPS evaluation rather than credential compromise.
