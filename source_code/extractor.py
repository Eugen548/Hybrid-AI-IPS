#!/usr/bin/env python3
"""
Feature extraction utility used to construct the fixed-length
input vector expected by the AI-IPS inference engine.
"""

import sys
import requests
import joblib

AI_SERVER_URL = "http://127.0.0.1:5000/event"
FEATURES_PATH = "/home/cyber1/ips-ai/src/ml/features.pkl"


def get_full_feature_vector(ip, captured_data):
    """
    Build a complete feature vector compatible with the trained models.

    Missing features are initialized to 0.0 in order to preserve
    the fixed feature ordering used during training and inference.
    """
    try:
        feature_names = joblib.load(FEATURES_PATH)
        full_features = {name: 0.0 for name in feature_names}

        for key, value in captured_data.items():
            if key in full_features:
                full_features[key] = float(value)

        full_features["ip"] = ip
        return full_features

    except Exception as error:
        print(f"[ERROR] Failed to build feature vector: {error}")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./extractor.py <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Example feature collection used for demonstration purposes.
    # In a deployment environment, these values can be replaced with
    # flow statistics extracted from CICFlowMeter, tshark, conntrack,
    # or similar monitoring tools.
    captured_data = {
        "Destination Port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 10,
        "SYN Flag Count": 1,
        "Fwd Packet Length Max": 1500,
        "Bwd Packet Length Min": 40
    }

    full_payload = get_full_feature_vector(target_ip, captured_data)

    if not full_payload:
        sys.exit(1)

    try:
        print(f"Submitting feature data for {target_ip}")
        response = requests.post(
            AI_SERVER_URL,
            json={"features": full_payload},
            timeout=5
        )

        if response.status_code == 200:
            result = response.json()
            action = result.get("action", "none")
            score = result.get("hybrid_score", 0.0)
            threshold = result.get("applied_threshold", 0.5)

            print(f"Server response: AI score {score:.4f}")
            print(f"Applied threshold: {threshold}")
            print(f"System decision: {action}")

        else:
            print(
                f"[ERROR] AI server returned "
                f"{response.status_code}: {response.text}"
            )

    except requests.exceptions.ConnectionError:
        print("[ERROR] Unable to connect to ai_server.py on port 5000.")

    except Exception as error:
        print(f"[ERROR] Communication error: {error}")
