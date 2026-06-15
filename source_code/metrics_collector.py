#!/usr/bin/env python3
import csv
import time
import os
import psutil
from datetime import datetime, timezone

OUT = os.getenv("METRICS_OUT", "/var/lib/ips-ai/metrics.csv")
INTERFACE = os.getenv("NET_IFACE", "ens192")
INTERVAL = float(os.getenv("INTERVAL", "1.0"))

TARGETS = {
    "ai_server": ["ai_server.py"],
    "ai_engine": ["ai_engine.py"],
    "fail2ban": ["fail2ban-server"],
}

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def bytes_to_mb(x):
    return x / (1024 * 1024)

def find_pid_lists():
    found = {k: [] for k in TARGETS}
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            name = p.info.get("name") or ""
            for key, needles in TARGETS.items():
                if any(n in cmd for n in needles) or any(n in name for n in needles):
                    found[key].append(p.info["pid"])
        except Exception:
            continue
    return found

def build_proc_cache():
    """
    Return:
      pid_lists: dict[str, list[int]]
      proc_cache: dict[int, psutil.Process]
    """
    pid_lists = find_pid_lists()
    proc_cache = {}

    for _, lst in pid_lists.items():
        for pid in lst:
            try:
                proc = psutil.Process(pid)
                proc.cpu_percent(interval=None)  # priming
                proc_cache[pid] = proc
            except Exception:
                continue

    return pid_lists, proc_cache

def agg_from_cache(key, pid_lists, proc_cache):
    cpus = 0.0
    rss_bytes = 0
    pid_list = pid_lists.get(key, [])

    for pid in pid_list:
        proc = proc_cache.get(pid)
        if proc is None:
            continue
        try:
            cpus += proc.cpu_percent(interval=None)
            rss_bytes += proc.memory_info().rss
        except Exception:
            continue

    return cpus, bytes_to_mb(rss_bytes), ",".join(map(str, pid_list))

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    header = [
        "ts_utc",

        # system-wide
        "cpu_percent_total",
        "mem_percent_total",
        "load1",
        "load5",
        "load15",
        "net_bytes_recv",
        "net_bytes_sent",
        "net_pkts_recv",
        "net_pkts_sent",

        # AI solution-level
        "ai_server_cpu_percent",
        "ai_server_rss_mb",
        "ai_engine_cpu_percent",
        "ai_engine_rss_mb",
        "ai_stack_cpu_percent",
        "ai_stack_rss_mb",

        # classic process visibility on AI node (optional)
        "fail2ban_cpu_percent",
        "fail2ban_rss_mb",

        # debugging / traceability
        "ai_server_pids",
        "ai_engine_pids",
        "fail2ban_pids",
    ]

    file_exists = os.path.exists(OUT)

    # priming pentru CPU total
    psutil.cpu_percent(interval=None)

    # construim cache-ul de procese o singură dată
    pid_lists, proc_cache = build_proc_cache()

    with open(OUT, "a", newline="") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(header)

        while True:
            ts = now_iso()

            cpu_total = psutil.cpu_percent(interval=0.2)
            mem_total = psutil.virtual_memory().percent

            try:
                load1, load5, load15 = os.getloadavg()
            except Exception:
                load1 = load5 = load15 = 0.0

            net = psutil.net_io_counters(pernic=True).get(INTERFACE)
            if net:
                nb_r, nb_s, np_r, np_s = (
                    net.bytes_recv, net.bytes_sent,
                    net.packets_recv, net.packets_sent
                )
            else:
                nb_r = nb_s = np_r = np_s = 0

            ai_server_cpu, ai_server_rss_mb, ai_server_pids = agg_from_cache("ai_server", pid_lists, proc_cache)
            ai_engine_cpu, ai_engine_rss_mb, ai_engine_pids = agg_from_cache("ai_engine", pid_lists, proc_cache)
            fail2ban_cpu, fail2ban_rss_mb, fail2ban_pids = agg_from_cache("fail2ban", pid_lists, proc_cache)

            ai_stack_cpu = ai_server_cpu + ai_engine_cpu
            ai_stack_rss_mb = ai_server_rss_mb + ai_engine_rss_mb

            w.writerow([
                ts,

                cpu_total,
                mem_total,
                load1,
                load5,
                load15,
                nb_r,
                nb_s,
                np_r,
                np_s,

                ai_server_cpu,
                ai_server_rss_mb,
                ai_engine_cpu,
                ai_engine_rss_mb,
                ai_stack_cpu,
                ai_stack_rss_mb,

                fail2ban_cpu,
                fail2ban_rss_mb,

                ai_server_pids,
                ai_engine_pids,
                fail2ban_pids,
            ])
            f.flush()
            time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
