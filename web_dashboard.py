import os
import time
import psutil
import datetime
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from pydantic import BaseModel

app = FastAPI(title="OwlEyeEngine - Cyber Security Dashboard", version="3.0.0")

# Shared state initialized by sentry.py
CORE_STATE = {
    "logger": None,
    "alerter": None,
    "proc_mon": None,
    "net_mon": None,
    "analyzer": None,
    "defender": None,
    "start_time": time.time()
}

def init_app_state(logger, alerter, proc_mon, net_mon, analyzer, defender):
    CORE_STATE["logger"] = logger
    CORE_STATE["alerter"] = alerter
    CORE_STATE["proc_mon"] = proc_mon
    CORE_STATE["net_mon"] = net_mon
    CORE_STATE["analyzer"] = analyzer
    CORE_STATE["defender"] = defender
    CORE_STATE["start_time"] = time.time()

# Request Models
class KillProcessRequest(BaseModel):
    pid: int
    reason: str = "Manual Admin Termination"

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Block"

class ToggleDefenseRequest(BaseModel):
    enabled: bool

# API Routes
@app.get("/api/status")
def get_status():
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
            
    # Sort by cpu/memory descending
    procs.sort(key=lambda x: (x['cpu'], x['memory']), reverse=True)
    return {"count": len(procs), "processes": procs[:limit]}

@app.get("/api/connections")
def get_connections():
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
    except Exception as e:
        pass

    return {"count": len(conns), "connections": conns}

@app.get("/api/threats")
def get_threats(limit: int = 50):
    analyzer = CORE_STATE.get("analyzer")
    if not analyzer:
        return {"threats": []}
    return {"threats": analyzer.get_recent_threats(limit)}

@app.get("/api/logs")
def get_logs(limit: int = 50):
    logger = CORE_STATE.get("logger")
    if not logger:
        return {"logs": []}
    return {"logs": logger.get_recent_logs(limit)}

@app.post("/api/defender/toggle")
def toggle_defense(req: ToggleDefenseRequest):
    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    defender.set_auto_defense(req.enabled)
    return {"success": True, "auto_defense": defender.auto_defense}

@app.post("/api/actions/kill")
def action_kill(req: KillProcessRequest):
    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    res = defender.kill_process(req.pid, reason=req.reason)
    return res

@app.post("/api/actions/block_ip")
def action_block_ip(req: BlockIPRequest):
    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    res = defender.block_ip(req.ip, reason=req.reason)
    return res

@app.post("/api/actions/unblock_ip")
def action_unblock_ip(req: BlockIPRequest):
    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    res = defender.unblock_ip(req.ip)
    return res

# Mount Static Dashboard UI
dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard_app")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>OwlEyeEngine v3.0 API Operational</h1><p>Dashboard UI loading...</p>"

def run_server(host="0.0.0.0", port=8000):
    uvicorn.run(app, host=host, port=port, log_level="warning")

if __name__ == "__main__":
    print("Starting standalone Web Dashboard API on http://localhost:8000...")
    run_server()
