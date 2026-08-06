import time
import sys
import os
import threading
from hidden_logger import HiddenLogger
from process_monitor import ProcessMonitor
from network_monitor import NetworkMonitor
from alert_system import AlertSystem
from heuristic_analyzer import HeuristicAnalyzer
from active_defender import ActiveDefender
import web_dashboard

def start_dashboard_thread(logger, alerter, proc_mon, net_mon, analyzer, defender, port=8000):
    web_dashboard.init_app_state(logger, alerter, proc_mon, net_mon, analyzer, defender)
    print(f"[+] Launching Web Dashboard API on http://localhost:{port} (0.0.0.0:{port})")
    dashboard_thread = threading.Thread(
        target=web_dashboard.run_server,
        kwargs={"host": "0.0.0.0", "port": port},
        daemon=True
    )
    dashboard_thread.start()
    return dashboard_thread

def main():
    print("""
    ^...^
   / o o \\   OwlEyeEngine v3.0 - Global Edition
   |  Y  |   The Silent Hunter & Active Defense
    V v V    "Silent flight, 360° vision, total threat defense."
    """)
    print("[*] Initializing OwlEye Core Security Engine...")
    
    logger = HiddenLogger()
    alerter = AlertSystem() # Checks SENTRY_TELEGRAM_TOKEN/CHAT_ID
    proc_mon = ProcessMonitor()
    net_mon = NetworkMonitor()
    defender = ActiveDefender(auto_defense=False, logger=logger)
    analyzer = HeuristicAnalyzer(logger, alerter, defender=defender)
    
    # Start Web Dashboard
    dashboard_port = int(os.getenv("OWLEYE_PORT", 8000))
    start_dashboard_thread(logger, alerter, proc_mon, net_mon, analyzer, defender, port=dashboard_port)

    print("\n[+] OwlEye Engine actively monitoring system anomalies & network traffic.")
    print(f"[+] Open http://localhost:{dashboard_port} to access the Web Control Panel.\n")

    try:
        while True:
            # 1. Check Processes (htop style + Heuristics + Active Defense)
            new_procs = proc_mon.check_new_processes()
            for p in new_procs:
                logger.log_event(
                    "PROCESS_NEW", 
                    f"Name: {p['name']} | PID: {p['pid']}", 
                    p['path'], 
                    f"User: {p['user']}"
                )
                print(f"[!] Logged new process: {p['name']} (PID: {p['pid']})")
                analyzer.analyze_process_launch(p)

            # 2. Check Network (Cisco context + Heuristics + Active Defense)
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
                    print(f"[!] Logged new connection from: {c['remote']}")

            time.sleep(3)
            
    except KeyboardInterrupt:
        print("\nSentry Agent stopping cleanly...")
        sys.exit(0)
    except Exception as e:
        logger.log_event("CRITICAL_ERROR", str(e), "Main Loop", "System")
        print(f"[CRITICAL ERROR]: {e}")

if __name__ == "__main__":
    main()
