import os
import time
import psutil
import datetime
import secrets
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
from pydantic import BaseModel
from typing import Optional

DEMO_MODE = os.getenv("OWLEYE_DEMO_MODE", "false").lower() == "true"

app = FastAPI(
    title="OwlEyeEngine - Cyber Security Dashboard",
    version="3.0.0",
    docs_url="/api/docs" if DEMO_MODE else None,
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CORE_STATE = {
    "logger": None,
    "alerter": None,
    "proc_mon": None,
    "net_mon": None,
    "analyzer": None,
    "defender": None,
    "start_time": time.time()
}

ws_clients: list[WebSocket] = []

def init_app_state(logger, alerter, proc_mon, net_mon, analyzer, defender):
    CORE_STATE["logger"] = logger
    CORE_STATE["alerter"] = alerter
    CORE_STATE["proc_mon"] = proc_mon
    CORE_STATE["net_mon"] = net_mon
    CORE_STATE["analyzer"] = analyzer
    CORE_STATE["defender"] = defender
    CORE_STATE["start_time"] = time.time()

class KillProcessRequest(BaseModel):
    pid: int
    reason: str = "Manual Admin Termination"

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Block"

class ToggleDefenseRequest(BaseModel):
    enabled: bool

# --- DEMO DATA GENERATORS ---

def _demo_status():
    import random
    cpu = round(random.uniform(2, 25), 1)
    mem_pct = round(random.uniform(30, 65), 1)
    mem_used = round(psutil.virtual_memory().total / (1024*1024) * mem_pct / 100, 1)
    mem_total = round(psutil.virtual_memory().total / (1024*1024), 1)
    uptime_s = int(time.time() - CORE_STATE["start_time"])
    return {
        "engine": "OwlEyeEngine v3.0 Global Edition",
        "status": "OPERATIONAL",
        "uptime": str(datetime.timedelta(seconds=uptime_s)),
        "demo_mode": True,
        "system": {
            "cpu_percent": cpu,
            "memory_percent": mem_pct,
            "memory_used_mb": mem_used,
            "memory_total_mb": mem_total
        },
        "active_defense": {
            "auto_defense": True,
            "blocked_ips_count": 3,
            "terminated_pids_count": 2,
            "blocked_ips": ["45.33.32.156", "185.220.101.42", "198.51.100.7"]
        },
        "threat_summary": {
            "total_threats": 7,
            "recent_count": 3
        }
    }

def _demo_threats():
    return {
        "threats": [
            {"id": "THREAT-1725300001000", "timestamp": "2026-09-03 14:32:01", "type": "PORT_SCAN", "severity": "HIGH", "score": 85, "details": {"ip": "45.33.32.156", "connections_in_window": 12, "entry_point": "Network:45.33.32.156 -> LocalPort:22"}, "auto_mitigated": True},
            {"id": "THREAT-1725300002000", "timestamp": "2026-09-03 14:30:14", "type": "SUSPICIOUS_PATH_EXECUTION", "severity": "CRITICAL", "score": 92, "details": {"name": "payload.exe", "pid": 4921, "user": "root", "path": "/tmp/.hidden/payload.exe"}, "auto_mitigated": True},
            {"id": "THREAT-1725300003000", "timestamp": "2026-09-03 14:28:55", "type": "PORT_SCAN", "severity": "HIGH", "score": 78, "details": {"ip": "185.220.101.42", "connections_in_window": 8, "entry_point": "Network:185.220.101.42 -> LocalPort:443"}, "auto_mitigated": True},
            {"id": "THREAT-1725300004000", "timestamp": "2026-09-03 14:25:10", "type": "SUSPICIOUS_PATH_EXECUTION", "severity": "MEDIUM", "score": 65, "details": {"name": "miner.py", "pid": 3102, "user": "www-data", "path": "/var/tmp/miner.py"}, "auto_mitigated": False},
            {"id": "THREAT-1725300005000", "timestamp": "2026-09-03 14:20:33", "type": "PORT_SCAN", "severity": "HIGH", "score": 88, "details": {"ip": "198.51.100.7", "connections_in_window": 15, "entry_point": "Network:198.51.100.7 -> LocalPort:3306"}, "auto_mitigated": True},
        ]
    }

def _demo_processes():
    import random
    procs = [
        {"pid": 1, "name": "systemd", "user": "root", "path": "/lib/systemd/systemd", "cpu": 0.0, "memory": 0.3},
        {"pid": 234, "name": "nginx", "user": "www-data", "path": "/usr/sbin/nginx", "cpu": 1.2, "memory": 0.8},
        {"pid": 567, "name": "python3", "user": "root", "path": "/usr/bin/python3", "cpu": 3.4, "memory": 2.1},
        {"pid": 891, "name": "sshd", "user": "root", "path": "/usr/sbin/sshd", "cpu": 0.1, "memory": 0.4},
        {"pid": 1023, "name": "mysqld", "user": "mysql", "path": "/usr/sbin/mysqld", "cpu": 5.7, "memory": 8.3},
        {"pid": 1456, "name": "node", "user": "deploy", "path": "/usr/local/bin/node", "cpu": 2.1, "memory": 3.5},
        {"pid": 1789, "name": "docker-proxy", "user": "root", "path": "/usr/bin/docker-proxy", "cpu": 0.3, "memory": 1.2},
        {"pid": 2012, "name": "containerd", "user": "root", "path": "/usr/bin/containerd", "cpu": 0.8, "memory": 1.5},
    ]
    for p in procs:
        p["cpu"] = round(random.uniform(0.1, 8.0), 1)
        p["memory"] = round(random.uniform(0.1, 5.0), 1)
    return {"count": len(procs), "processes": procs}

def _demo_connections():
    return {
        "count": 5,
        "connections": [
            {"fd": 12, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:8000", "remote": "192.168.1.50:54321", "remote_ip": "192.168.1.50", "remote_port": 54321, "status": "ESTABLISHED", "pid": 567},
            {"fd": 14, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:443", "remote": "10.0.0.15:8080", "remote_ip": "10.0.0.15", "remote_port": 8080, "status": "ESTABLISHED", "pid": 234},
            {"fd": 18, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:3306", "remote": "172.16.0.5:49152", "remote_ip": "172.16.0.5", "remote_port": 49152, "status": "ESTABLISHED", "pid": 1023},
            {"fd": 22, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:22", "remote": "45.33.32.156:1337", "remote_ip": "45.33.32.156", "remote_port": 1337, "status": "SYN_RECV", "pid": 891},
            {"fd": 25, "family": "IPv6", "type": "TCP", "local": ":::8080", "remote": "203.0.113.42:22", "remote_ip": "203.0.113.42", "remote_port": 22, "status": "ESTABLISHED", "pid": 567},
        ]
    }

def _demo_logs():
    return {
        "logs": [
            "[2026-09-03 14:32:01] EVENT: SECURITY_HEURISTIC | WHAT: PORT_SCAN | WHERE: 45.33.32.156 | ENTRY_POINT: Heuristic Motor",
            "[2026-09-03 14:30:14] EVENT: SECURITY_HEURISTIC | WHAT: SUSPICIOUS_PATH_EXECUTION | WHERE: payload.exe | ENTRY_POINT: PID: 4921 | Path: /tmp/.hidden/payload.exe",
            "[2026-09-03 14:28:55] EVENT: SECURITY_HEURISTIC | WHAT: PORT_SCAN | WHERE: 185.220.101.42 | ENTRY_POINT: Heuristic Motor",
            "[2026-09-03 14:25:10] EVENT: ACTIVE_DEFENSE | WHAT: PROCESS_KILLED | WHERE: PID: 4921 (payload.exe) | ENTRY_POINT: Automated mitigation",
            "[2026-09-03 14:20:33] EVENT: ACTIVE_DEFENSE | WHAT: IP_BLOCKED | WHERE: 185.220.101.42 | ENTRY_POINT: Automated mitigation: Port scanning",
            "[2026-09-03 14:15:00] EVENT: PROCESS_NEW | WHAT: Name: nginx | PID: 234 | WHERE: /usr/sbin/nginx | ENTRY_POINT: User: www-data",
            "[2026-09-03 14:10:22] EVENT: NETWORK_ENTRY | WHAT: Remote: 10.0.0.15:8080 | WHERE: Local: 0.0.0.0:443 | ENTRY_POINT: Network:10.0.0.15 -> LocalPort:443",
        ]
    }

# --- API ROUTES ---

@app.get("/api/status")
def get_status():
    if DEMO_MODE:
        return _demo_status()

    uptime_seconds = int(time.time() - CORE_STATE["start_time"])
    uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    defender = CORE_STATE.get("defender")
    analyzer = CORE_STATE.get("analyzer")

    return {
        "engine": "OwlEyeEngine v3.0 Global Edition",
        "status": "OPERATIONAL",
        "uptime": uptime_str,
        "demo_mode": False,
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / (1024 * 1024), 1),
            "memory_total_mb": round(mem.total / (1024 * 1024), 1)
        },
        "active_defense": {
            "auto_defense": defender.auto_defense if defender else False,
            "blocked_ips_count": len(defender.blocked_ips) if defender else 0,
            "terminated_pids_count": len(defender.terminated_pids) if defender else 0,
            "blocked_ips": list(defender.blocked_ips) if defender else []
        },
        "threat_summary": {
            "total_threats": len(analyzer.threat_history) if analyzer else 0,
            "recent_count": len(analyzer.get_recent_threats(10)) if analyzer else 0
        }
    }

@app.get("/api/processes")
def get_processes(limit: int = 50):
    if DEMO_MODE:
        return _demo_processes()

    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append({
                "pid": info['pid'],
                "name": info['name'] or "Unknown",
                "user": info['username'] or "N/A",
                "path": info['exe'] or "Unknown",
                "cpu": round(info['cpu_percent'] or 0.0, 1),
                "memory": round(info['memory_percent'] or 0.0, 1)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: (x['cpu'], x['memory']), reverse=True)
    return {"count": len(procs), "processes": procs[:limit]}

@app.get("/api/connections")
def get_connections():
    if DEMO_MODE:
        return _demo_connections()

    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.raddr:
                conns.append({
                    "fd": c.fd,
                    "family": "IPv4" if c.family == 2 else "IPv6",
                    "type": "TCP" if c.type == 1 else "UDP",
                    "local": f"{c.laddr.ip}:{c.laddr.port}",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "status": c.status,
                    "pid": c.pid
                })
    except Exception:
        pass

    return {"count": len(conns), "connections": conns}

@app.get("/api/threats")
def get_threats(limit: int = 50):
    if DEMO_MODE:
        return _demo_threats()

    analyzer = CORE_STATE.get("analyzer")
    if not analyzer:
        return {"threats": []}
    return {"threats": analyzer.get_recent_threats(limit)}

@app.get("/api/logs")
def get_logs(limit: int = 50):
    if DEMO_MODE:
        return _demo_logs()

    logger = CORE_STATE.get("logger")
    if not logger:
        return {"logs": []}
    return {"logs": logger.get_recent_logs(limit)}

@app.post("/api/defender/toggle")
def toggle_defense(req: ToggleDefenseRequest):
    if DEMO_MODE:
        return {"success": True, "auto_defense": req.enabled}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    defender.set_auto_defense(req.enabled)
    return {"success": True, "auto_defense": defender.auto_defense}

@app.post("/api/actions/kill")
def action_kill(req: KillProcessRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] Process PID {req.pid} terminated.", "pid": req.pid, "name": "demo_process"}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.kill_process(req.pid, reason=req.reason)

@app.post("/api/actions/block_ip")
def action_block_ip(req: BlockIPRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] IP {req.ip} blocked in firewall."}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.block_ip(req.ip, reason=req.reason)

@app.post("/api/actions/unblock_ip")
def action_unblock_ip(req: BlockIPRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] IP {req.ip} unblocked."}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.unblock_ip(req.ip)

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        while True:
            if DEMO_MODE:
                data = _demo_status()
            else:
                uptime_s = int(time.time() - CORE_STATE["start_time"])
                data = {
                    "cpu": psutil.cpu_percent(interval=None),
                    "memory": psutil.virtual_memory().percent,
                    "uptime": str(datetime.timedelta(seconds=uptime_s)),
                }
            await websocket.send_json(data)
            await websocket.sleep(2)
    except WebSocketDisconnect:
        ws_clients.remove(websocket)
    except Exception:
        if websocket in ws_clients:
            ws_clients.remove(websocket)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dashboard_dir = os.path.join(BASE_DIR, "dashboard_app")
landing_dir = os.path.join(BASE_DIR, "landing_page")

# Mount static dashboard
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

# Mount landing static assets
if os.path.exists(landing_dir):
    app.mount("/landing", StaticFiles(directory=landing_dir), name="landing-static")

def _read_html(directory, filename="index.html"):
    index_file = os.path.join(directory, filename)
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return None

@app.get("/", response_class=HTMLResponse)
def serve_landing():
    html = _read_html(landing_dir)
    if html:
        return html
    return "<h1>OwlEyeEngine v3.0</h1><p><a href='/dashboard'>Open Dashboard</a></p>"

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    html = _read_html(dashboard_dir)
    if html:
        return html
    return "<h1>OwlEyeEngine Dashboard</h1>"

@app.get("/health")
def health_check():
    return {"status": "ok", "version": "3.0.0", "demo_mode": DEMO_MODE}

def run_server(host="0.0.0.0", port=8000):
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)

if __name__ == "__main__":
    print(f"Starting OwlEyeEngine Web Dashboard {'(DEMO MODE)' if DEMO_MODE else ''} on http://localhost:8000...")
    run_server()
