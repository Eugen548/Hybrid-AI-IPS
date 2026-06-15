#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import struct
import socket
import ipaddress
import logging
import tempfile
import requests
import ctypes
import subprocess
from flask import Flask, request, jsonify, render_template

# -----------------------------------------------------------------------------
# Runtime configuration
# -----------------------------------------------------------------------------
app = Flask(__name__, template_folder="/home/cyber1/ips-ai/src/dashboard/templates")

AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", "http://127.0.0.1:5001/predict")
BPF_MAP_PATH = os.getenv("BPF_MAP_PATH", "/sys/fs/bpf/xdp_block")
META_PATH = os.getenv("META_PATH", "/var/lib/ips-ai/blacklist_meta.json")
DYNAMIC_CONFIG_PATH = os.getenv("DYNAMIC_CONFIG_PATH", "/var/lib/ips-ai/dynamic_config.json")

LAB_MODE = os.getenv("LAB_MODE", "0") == "1"
WHITELIST = json.loads(os.getenv("WHITELIST_JSON", '["192.168.1.100"]'))

DEFAULT_INTERNALS = ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]
INTERNAL_NETWORKS = [] if LAB_MODE else json.loads(os.getenv("INTERNAL_NETWORKS_JSON", json.dumps(DEFAULT_INTERNALS)))

os.makedirs(os.path.dirname(META_PATH), exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai-ips")

# -----------------------------------------------------------------------------
# libbcc via ctypes
# -----------------------------------------------------------------------------
lib = ctypes.CDLL("libbcc.so.0")

lib.bpf_obj_get.argtypes = [ctypes.c_char_p]
lib.bpf_obj_get.restype = ctypes.c_int

lib.bpf_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong]
lib.bpf_update_elem.restype = ctypes.c_int

lib.bpf_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
lib.bpf_delete_elem.restype = ctypes.c_int

lib.bpf_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
lib.bpf_lookup_elem.restype = ctypes.c_int


def ensure_bpf_map_exists():
    return os.path.exists(BPF_MAP_PATH)


def ip_to_be32(ip):
    return int.from_bytes(socket.inet_aton(ip), "big")


def _map_fd():
    fd = lib.bpf_obj_get(BPF_MAP_PATH.encode())
    if fd < 0:
        raise RuntimeError("Failed to open BPF map")
    return fd


def bpf_lookup(fd, ip):
    key = struct.pack(">I", ip_to_be32(ip))
    val = bytearray(8)
    rc = lib.bpf_lookup_elem(fd, ctypes.c_char_p(key), (ctypes.c_char * 8).from_buffer(val))
    if rc != 0:
        return None
    return struct.unpack("<Q", val)[0]


def bpf_update(fd, ip):
    key = struct.pack(">I", ip_to_be32(ip))
    val = struct.pack("<Q", 0)
    rc = lib.bpf_update_elem(fd, ctypes.c_char_p(key), ctypes.c_char_p(val), 0)
    if rc != 0:
        raise RuntimeError("bpf_update_elem failed")


def bpf_delete(fd, ip):
    key = struct.pack(">I", ip_to_be32(ip))
    return lib.bpf_delete_elem(fd, ctypes.c_char_p(key)) == 0


# -----------------------------------------------------------------------------
# META
# -----------------------------------------------------------------------------
def load_meta():
    if not os.path.exists(META_PATH):
        return {}
    with open(META_PATH, "r") as f:
        return json.load(f)


def save_meta(data):
    fd, tmp = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, META_PATH)


# -----------------------------------------------------------------------------
# ROUTES
# -----------------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ai_engine": AI_ENGINE_URL,
        "bpf_map_exists": ensure_bpf_map_exists(),
        "lab_mode": LAB_MODE,
        "running_as_root": os.geteuid() == 0
    })

@app.route("/event", methods=["POST"])
def event():
    data = request.json
    features = data.get("features", {})
    ip = features.pop("ip", None)

    if not ip:
        return jsonify({"error": "missing ip"}), 400

    # Load the runtime decision threshold.
    try:
        threshold = json.load(open(DYNAMIC_CONFIG_PATH))["threshold"]
    except:
        threshold = 0.5

    # Forward the feature vector to the AI inference engine.
    r = requests.post(AI_ENGINE_URL, json={"features": features})
    ai_res = r.json()

    hybrid = float(ai_res.get("hybrid_score", 0))

   # Apply the same decision threshold used by the enforcement logic.
    would_block = hybrid > threshold
    decision_status = "malicious" if would_block else "benign"

    meta = load_meta()
    meta[ip] = {
        **ai_res,
        "applied_threshold": threshold,
        "status": decision_status,
        "action": "blocked_at_threshold" if would_block else "monitored"
    }
    save_meta(meta)

    if would_block:
        fd = _map_fd()
        try:
            if bpf_lookup(fd, ip) is None:
                bpf_update(fd, ip)
        finally:
            os.close(fd)
        
        return jsonify({
            **ai_res,
            "status": decision_status,
            "action": "blocked_at_threshold"
        })

    return jsonify({
        **ai_res,
        "status": decision_status,
        "action": "monitored"
    })        
    

@app.route("/unban", methods=["POST"])
def unban():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    fd = _map_fd()
    try:
        bpf_delete(fd, ip)
    finally:
        os.close(fd)

    meta = load_meta()
    meta.pop(ip, None)
    save_meta(meta)

    return jsonify({"status": "cleared"})

@app.route("/kernel_blocked")
def kernel_blocked():
    if not ensure_bpf_map_exists():
        return jsonify([])

    try:
        result = subprocess.check_output(
            ["bpftool", "map", "dump", "pinned", BPF_MAP_PATH, "-j"],
            text=True
        )
        entries = json.loads(result) if result else []
    except Exception as e:
        logger.exception("Failed to dump pinned BPF map")
        return jsonify([])

    meta = load_meta()
    output = []

    def decode_bpftool_key_to_ip(raw):
        if isinstance(raw, int):
            try:
                return socket.inet_ntoa(raw.to_bytes(4, "little"))
            except Exception:
                return None

        if isinstance(raw, str):
            try:
                # bpftool may return the key as a numeric string.
                num = int(raw)
                return socket.inet_ntoa(num.to_bytes(4, "little"))
            except Exception:
                return None

        if isinstance(raw, list) and len(raw) == 4:
            try:
                vals = [int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x) for x in raw]
                return ".".join(str(v) for v in vals)
            except Exception:
                return None

        return None

    for e in entries:
        raw = e.get("key")
        value = e.get("value", 0)

        try:
            value_int = int(value)
        except Exception:
            value_int = 0

        ip = decode_bpftool_key_to_ip(raw)
        if not ip:
            continue

        data = meta.get(ip, {})
        output.append({
            "ip": ip,
            "count": value_int,
            **data
        })

    return jsonify(output)

@app.route("/events")
def events():
    meta = load_meta()
    return jsonify([{ "ip": ip, **data } for ip, data in meta.items()])


if __name__ == "__main__":
    logger.info("Starting AI-IPS enforcement server")
    app.run(host="0.0.0.0", port=5000)
