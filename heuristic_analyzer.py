import time
from collections import defaultdict
import datetime

class HeuristicAnalyzer:
    def __init__(self, logger, alerter, defender=None):
        self.logger = logger
        self.alerter = alerter
        self.defender = defender
        self.ip_connection_counts = defaultdict(list) # IP -> list of timestamps
        self.port_scan_threshold = 5 # connections to different ports in a short time
        self.time_window = 60 # seconds
        self.known_ips = {"127.0.0.1", "0.0.0.0", "::1"}
        self.threat_history = []
        self.max_history = 100

    def record_threat(self, threat_type: str, severity: str, score: int, details: dict, auto_mitigated: bool = False):
        event = {
            "id": f"THREAT-{int(time.time()*1000)}",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": threat_type,
            "severity": severity,
            "score": score,
            "details": details,
            "auto_mitigated": auto_mitigated
        }
        self.threat_history.insert(0, event)
        if len(self.threat_history) > self.max_history:
            self.threat_history.pop()
        return event

    def get_recent_threats(self, limit=50):
        return self.threat_history[:limit]

    def analyze_connections(self, new_connections):
        """
        Analyze connection patterns for anomalies like port scanning or malicious IPs.
        """
        for conn in new_connections:
            remote = conn.get('remote', '')
            if not remote or ':' not in remote:
                continue
                
            remote_ip = remote.split(':')[0]
            if remote_ip in self.known_ips:
                continue
                
            current_time = time.time()
            self.ip_connection_counts[remote_ip].append(current_time)
            
            # Clean up old timestamps
            self.ip_connection_counts[remote_ip] = [
                t for t in self.ip_connection_counts[remote_ip] 
                if current_time - t < self.time_window
            ]
            
            # Check for high frequency (potential scan)
            count = len(self.ip_connection_counts[remote_ip])
            if count >= self.port_scan_threshold:
                alert_msg = (
                    f"POTENTIAL SCAN DETECTED!\n"
                    f"Source IP: {remote_ip}\n"
                    f"Activity: {count} connections in {self.time_window}s"
                )
                self.logger.log_event("SECURITY_HEURISTIC", "PORT_SCAN", remote_ip, "Heuristic Motor")
                self.alerter.send_alert(alert_msg)
                print(f"[!!!] {alert_msg}")
                
                auto_mitigated = False
                if self.defender and self.defender.auto_defense:
                    res = self.defender.block_ip(remote_ip, reason="Automated mitigation: Port scanning threshold reached")
                    auto_mitigated = res.get("success", False)

                self.record_threat(
                    threat_type="PORT_SCAN",
                    severity="HIGH",
                    score=85,
                    details={"ip": remote_ip, "connections_in_window": count, "entry_point": conn.get("entry_point")},
                    auto_mitigated=auto_mitigated
                )

                # Reset count to avoid alert spamming
                self.ip_connection_counts[remote_ip] = []

    def analyze_process_launch(self, process_info):
        """
        Analyze process launches for unusual behavior or high risk paths.
        """
        path = (process_info.get('path') or "").lower()
        proc_name = process_info.get('name', 'Unknown')
        pid = process_info.get('pid', 0)
        user = process_info.get('user', 'Unknown')

        suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'hidden', '/tmp', '/var/tmp']
        
        is_suspicious = any(sp in path for sp in suspicious_paths)
        if is_suspicious:
            alert_msg = (
                f"SUSPICIOUS PROCESS PATH!\n"
                f"Name: {proc_name} (PID: {pid})\n"
                f"User: {user}\n"
                f"Path: {process_info.get('path')}"
            )
            self.logger.log_event("SECURITY_HEURISTIC", "SUSPICIOUS_PATH", proc_name, f"PID: {pid} | Path: {path}")
            self.alerter.send_alert(alert_msg)
            print(f"[!!!] {alert_msg}")

            auto_mitigated = False
            if self.defender and self.defender.auto_defense:
                res = self.defender.kill_process(pid, reason="Automated mitigation: Process launched from temp/hidden directory")
                auto_mitigated = res.get("success", False)

            self.record_threat(
                threat_type="SUSPICIOUS_PATH_EXECUTION",
                severity="CRITICAL" if "temp" in path else "MEDIUM",
                score=90 if "temp" in path else 70,
                details={"name": proc_name, "pid": pid, "user": user, "path": process_info.get('path')},
                auto_mitigated=auto_mitigated
            )
