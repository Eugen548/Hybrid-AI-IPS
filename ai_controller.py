import requests
import sys

# URL of the AI server responsible for decision and enforcement.
AI_SERVER_URL = "http://127.0.0.1:5000/event"


def ban_ip(ip):
    """
    Submit an IP address for evaluation by the AI-IPS framework.
    """

    # Example payload used to trigger evaluation.
    # Runtime flow statistics can be added in a deployment environment.
    payload = {
        "features": {
            "ip": ip,
            "Destination Port": 80,
            "Flow Duration": 1000,
            "Total Fwd Packets": 10
        }
    }

    try:
        response = requests.post(
            AI_SERVER_URL,
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            res_data = response.json()

            print(
                f"[INFO] IP {ip} evaluated. "
                f"Action: {res_data.get('action')}"
            )
            print(
                f"[INFO] Hybrid score: "
                f"{res_data.get('hybrid_score')}"
            )

        else:
            print(
                f"[ERROR] Server error: "
                f"{response.status_code} - {response.text}"
            )

    except Exception as error:
        print(f"[ERROR] Connection error to AI server: {error}")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--ban":
        ban_ip(sys.argv[2])
    else:
        print("Usage: python3 ai_controller.py --ban <IP>")