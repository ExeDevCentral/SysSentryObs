import time
import sys
import os
import signal
import threading
from hidden_logger import HiddenLogger
from process_monitor import ProcessMonitor
from network_monitor import NetworkMonitor
from alert_system import AlertSystem
from heuristic_analyzer import HeuristicAnalyzer
from active_defender import ActiveDefender
import web_dashboard

BANNER = r"""
    ^...^
   / o o \   OwlEyeEngine v3.0 - Global Edition
   |  Y  |   The Silent Hunter & Active Defense
    V v V    "Silent flight, 360° vision, total threat defense."
"""

def start_dashboard_thread(logger, alerter, proc_mon, net_mon, analyzer, defender, port=8000):
    web_dashboard.init_app_state(logger, alerter, proc_mon, net_mon, analyzer, defender)
    print(f"[+] Web Dashboard API on http://0.0.0.0:{port}")
    thread = threading.Thread(
        target=web_dashboard.run_server,
        kwargs={"host": "0.0.0.0", "port": port},
        daemon=True
    )
    thread.start()
    return thread

def main():
    demo_mode = os.getenv("OWLEYE_DEMO_MODE", "false").lower() == "true"

    print(BANNER)
    print(f"[*] Mode: {'DEMO (simulated data)' if demo_mode else 'LIVE (real monitoring)'}")
    print("[*] Initializing OwlEye Core Security Engine...")

    logger = HiddenLogger() if not demo_mode else None
    alerter = AlertSystem() if not demo_mode else None
    proc_mon = ProcessMonitor() if not demo_mode else None
    net_mon = NetworkMonitor() if not demo_mode else None
    defender = ActiveDefender(auto_defense=False, logger=logger) if not demo_mode else None
    analyzer = HeuristicAnalyzer(logger, alerter, defender=defender) if not demo_mode else None

    dashboard_port = int(os.getenv("OWLEYE_PORT", 8000))
    start_dashboard_thread(logger, alerter, proc_mon, net_mon, analyzer, defender, port=dashboard_port)

    print(f"\n[+] OwlEye Engine {'DEMO' if demo_mode else 'actively monitoring'} system anomalies & network traffic.")
    print(f"[+] Dashboard: http://localhost:{dashboard_port}\n")

    if demo_mode:
        print("[*] Running in DEMO mode. Simulated data only. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Sentry Agent stopping cleanly...")
            sys.exit(0)
        return

    def shutdown(sig, frame):
        print("\n[*] Sentry Agent stopping cleanly...")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            new_procs = proc_mon.check_new_processes()
            for p in new_procs:
                logger.log_event(
                    "PROCESS_NEW",
                    f"Name: {p['name']} | PID: {p['pid']}",
                    p['path'],
                    f"User: {p['user']}"
                )
                print(f"[!] New process: {p['name']} (PID: {p['pid']})")
                analyzer.analyze_process_launch(p)

            new_conns = net_mon.check_new_connections()
            if new_conns:
                analyzer.analyze_connections(new_conns)
                for c in new_conns:
                    logger.log_event(
                        "NETWORK_ENTRY",
                        f"Remote: {c['remote']}",
                        f"Local: {c['local']}",
                        c['entry_point']
                    )
                    print(f"[!] New connection from: {c['remote']}")

            time.sleep(3)

    except KeyboardInterrupt:
        print("\n[*] Sentry Agent stopping cleanly...")
        sys.exit(0)
    except Exception as e:
        if logger:
            logger.log_event("CRITICAL_ERROR", str(e), "Main Loop", "System")
        print(f"[CRITICAL ERROR]: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
