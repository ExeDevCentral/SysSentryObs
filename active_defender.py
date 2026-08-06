import os
import sys
import psutil
import subprocess
import platform
import logging

class ActiveDefender:
    """
    Active Defense and Mitigation Module for OwlEyeEngine.
    Handles process termination, IP blocking, and automated quarantine actions.
    """
    def __init__(self, auto_defense=False, logger=None):
        self.auto_defense = auto_defense
        self.logger = logger
        self.blocked_ips = set()
        self.terminated_pids = set()

    def is_windows(self):
        return platform.system().lower() == "windows"

    def set_auto_defense(self, enabled: bool):
        self.auto_defense = enabled
        print(f"[!] Active Defense Mode changed to: {'ENABLED (AUTO-MITIGATION)' if enabled else 'DISABLED (ALERT ONLY)'}")

    def kill_process(self, pid: int, reason: str = "Heuristic anomaly detected") -> dict:
        """
        Attempts to terminate a target process by PID safely.
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_path = proc.exe() if hasattr(proc, 'exe') else "Unknown"

            # Prevent killing critical system processes
            protected = ["system", "idle", "explorer.exe", "svchost.exe", "init", "systemd", "python.exe", "pythonw.exe"]
            if proc_name.lower() in protected or pid <= 4:
                return {
                    "success": False,
                    "message": f"Refused to kill protected system process '{proc_name}' (PID {pid})"
                }

            proc.kill()
            proc.wait(timeout=3)
            self.terminated_pids.add(pid)

            log_msg = f"TERMINATED PID {pid} ({proc_name}) | Path: {proc_path} | Reason: {reason}"
            if self.logger:
                self.logger.log_event("ACTIVE_DEFENSE", "PROCESS_KILLED", f"PID: {pid} ({proc_name})", reason)

            print(f"[🛡️ DEFENDER] {log_msg}")
            return {"success": True, "message": log_msg, "pid": pid, "name": proc_name}

        except psutil.NoSuchProcess:
            return {"success": False, "message": f"Process PID {pid} no longer exists."}
        except psutil.AccessDenied:
            return {"success": False, "message": f"Access Denied to terminate PID {pid}. Admin/Root privileges required."}
        except Exception as e:
            return {"success": False, "message": f"Failed to terminate PID {pid}: {str(e)}"}

    def block_ip(self, ip: str, reason: str = "Port scan or unauthorized connection") -> dict:
        """
        Blocks an incoming IP address on the host firewall.
        Windows: netsh advfirewall firewall
        Linux: iptables / ufw
        """
        if ip in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
            return {"success": False, "message": "Cannot block loopback IP"}

        if ip in self.blocked_ips:
            return {"success": True, "message": f"IP {ip} is already blocked."}

        rule_name = f"OwlEye_Block_{ip.replace('.', '_')}"

        try:
            if self.is_windows():
                # Windows Firewall rule creation
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "enable=yes"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    self.blocked_ips.add(ip)
                    if self.logger:
                        self.logger.log_event("ACTIVE_DEFENSE", "IP_BLOCKED", ip, reason)
                    return {"success": True, "message": f"Successfully blocked IP {ip} via Windows Firewall"}
                else:
                    # Non-admin or firewall disabled warning
                    self.blocked_ips.add(ip) # Track logically
                    return {"success": True, "message": f"Tracked blocked IP {ip} (Firewall rule required Admin privileges)"}
            else:
                # Linux iptables block rule
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    self.blocked_ips.add(ip)
                    if self.logger:
                        self.logger.log_event("ACTIVE_DEFENSE", "IP_BLOCKED", ip, reason)
                    return {"success": True, "message": f"Successfully blocked IP {ip} via iptables"}
                else:
                    self.blocked_ips.add(ip)
                    return {"success": True, "message": f"Tracked blocked IP {ip} (iptables required root privileges)"}

        except Exception as e:
            return {"success": False, "message": f"Error executing firewall command for {ip}: {str(e)}"}

    def unblock_ip(self, ip: str) -> dict:
        """
        Removes firewall rule for blocked IP.
        """
        if ip not in self.blocked_ips:
            return {"success": False, "message": f"IP {ip} is not in blocked list."}

        rule_name = f"OwlEye_Block_{ip.replace('.', '_')}"
        try:
            if self.is_windows():
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True)
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True)

            self.blocked_ips.remove(ip)
            if self.logger:
                self.logger.log_event("ACTIVE_DEFENSE", "IP_UNBLOCKED", ip, "Manual Admin Action")
            return {"success": True, "message": f"Unblocked IP {ip}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to unblock {ip}: {str(e)}"}

if __name__ == "__main__":
    defender = ActiveDefender(auto_defense=False)
    print(f"Active Defender initialized. Auto Defense: {defender.auto_defense}")
