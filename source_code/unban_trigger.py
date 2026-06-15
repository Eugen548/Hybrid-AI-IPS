#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import requests

# Unban goes ONLY to ai_server (port 5000). ai_server (root) handles eBPF map + meta.
AI_SERVER_URL = os.getenv("AI_SERVER_URL", "http://127.0.0.1:5000/unban")

def main():
    if len(sys.argv) < 2:
        print("Usage: unban_trigger.py <ip>")
        sys.exit(1)

    ip = sys.argv[1].strip()
    if not ip:
        print("[!] Empty IP")
        sys.exit(1)

    try:
        r = requests.post(AI_SERVER_URL, json={"ip": ip}, timeout=5)
        if r.status_code == 200:
            print(f"[+] Unban sent to ai_server for {ip}.")
            sys.exit(0)
        else:
            print(f"[!] ai_server responded {r.status_code}: {r.text}")
            sys.exit(2)
    except Exception as e:
        print(f"[!] Could not contact ai_server: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
