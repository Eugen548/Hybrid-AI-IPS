#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import joblib
import numpy as np
import shap
import tensorflow as tf
from collections import deque, defaultdict
import os

app = Flask(__name__)

MODEL_PATH = os.getenv("MODEL_PATH", "/home/cyber1/ips-ai/src/ml")
FEATURES_PATH = os.getenv("FEATURES_PATH", f"{MODEL_PATH}/features.pkl")

SEQUENCE_LENGTH = int(os.getenv("SEQUENCE_LENGTH", "10"))
DEFAULT_THRESHOLD = float(os.getenv("ENGINE_THRESHOLD", "0.5"))

# Runtime history is maintained using a shared sequence buffer.
# Incoming observations contribute to the same temporal context.
history_buffers = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))

# Load trained models and preprocessing artifacts.
rf_model = joblib.load(f"{MODEL_PATH}/rf_model.pkl")
scaler = joblib.load(f"{MODEL_PATH}/scaler.pkl")
lstm_model = tf.keras.models.load_model(f"{MODEL_PATH}/lstm_model.h5")

# Official feature order used during training.
FEATURE_ORDER = joblib.load(FEATURES_PATH)

# Initialize SHAP explanations for the RF component.
ENABLE_SHAP = os.getenv("ENABLE_SHAP", "1") == "1"
explainer = shap.TreeExplainer(rf_model, feature_perturbation="tree_path_dependent") if ENABLE_SHAP else None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_path": MODEL_PATH,
        "sequence_length": SEQUENCE_LENGTH,
        "num_features": len(FEATURE_ORDER),
        "enable_shap": ENABLE_SHAP
    }), 200


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "unknown")
    features_received = data.get("features", {})

    if not isinstance(features_received, dict) or not features_received:
        return jsonify({"error": "No features received"}), 400

    # Construct the feature vector using the training feature order.
    try:
        input_values = [float(features_received.get(f, 0.0)) for f in FEATURE_ORDER]
    except Exception:
        return jsonify({"error": "Invalid feature value"}), 400

    X = np.array([input_values], dtype="float32")

  # Apply feature scaling.
    try:
        X_scaled = scaler.transform(X)
    except Exception as e:
        return jsonify({"error": f"Scaler transform failed: {str(e)}"}), 500

   # Random Forest inference 
    rf_proba = float(rf_model.predict_proba(X_scaled)[0][1])

  # LSTM inference using a per-IP sliding window 
    buf = history_buffers[ip]
    buf.append(X_scaled[0])

    if len(buf) < SEQUENCE_LENGTH:
        temp_seq = [X_scaled[0]] * SEQUENCE_LENGTH
        X_lstm_input = np.array([temp_seq], dtype="float32")
    else:
        X_lstm_input = np.array([list(buf)], dtype="float32")

    try:
        lstm_proba = float(lstm_model.predict(X_lstm_input, verbose=0)[0][0])
    except Exception as e:
        return jsonify({"error": f"LSTM predict failed: {str(e)}"}), 500

    hybrid_score = float((rf_proba + lstm_proba) / 2.0)

   # SHAP top features for the RF component only 
    top_shap = {}
    if ENABLE_SHAP and explainer is not None:
        try:
            shap_values = explainer.shap_values(X_scaled)
            current_shap = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

            shap_dict = {FEATURE_ORDER[i]: float(current_shap[i]) for i in range(len(FEATURE_ORDER))}
            top_shap = dict(sorted(shap_dict.items(), key=lambda item: abs(item[1]), reverse=True)[:5])
        except Exception:
            top_shap = {}

    return jsonify({
        "rf_score": rf_proba,
        "lstm_score": lstm_proba,
        "hybrid_score": hybrid_score,
        "top_features_impact": top_shap,
        "status": "attack" if hybrid_score > DEFAULT_THRESHOLD else "benign"
    }), 200


@app.route("/reset_ip", methods=["POST"])
def reset_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "No IP"}), 400
    history_buffers.pop(ip, None)
    return jsonify({"status": "ok", "message": f"buffer cleared for {ip}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
