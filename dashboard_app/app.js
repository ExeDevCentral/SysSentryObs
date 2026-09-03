// OwlEyeEngine Dashboard Client v3.0

document.addEventListener("DOMContentLoaded", () => {
    fetchStatus();
    fetchThreats();
    fetchProcesses();
    fetchConnections();
    fetchLogs();

    setInterval(fetchStatus, 4000);
    setInterval(fetchThreats, 6000);
});

let allProcesses = [];
let wsConnection = null;

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

    const btn = Array.from(document.querySelectorAll(".tab-btn")).find(b => b.getAttribute("onclick")?.includes(tabId));
    if (btn) btn.classList.add("active");

    const tab = document.getElementById(`tab-${tabId}`);
    if (tab) tab.classList.add("active");

    if (tabId === 'processes') fetchProcesses();
    if (tabId === 'network') fetchConnections();
    if (tabId === 'logs') fetchLogs();
}

let wsAttempts = 0;

function tryWebSocket() {
    // WebSocket may be unavailable (e.g. Vercel serverless). Polling already
    // refreshes live data, so treat WebSocket as a non-critical enhancement.
    if (!('WebSocket' in window)) return;
    if (wsConnection && wsConnection.readyState === WebSocket.OPEN) return;
    if (wsAttempts >= 3) return; // give up quietly after a few tries

    wsAttempts++;
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try {
        wsConnection = new WebSocket(`${protocol}//${location.host}/ws/live`);

        wsConnection.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                updateLiveStats(data);
            } catch (e) {}
        };

        wsConnection.onopen = () => { wsAttempts = 0; };
        wsConnection.onclose = () => { wsConnection = null; };
        wsConnection.onerror = () => { wsConnection = null; };
    } catch (e) {
        wsConnection = null;
    }
}

function updateLiveStats(data) {
    if (data.cpu !== undefined) {
        document.getElementById("cpuVal").innerText = `${data.cpu}%`;
        document.getElementById("cpuBar").style.width = `${data.cpu}%`;
    }
    if (data.memory !== undefined) {
        document.getElementById("memBar").style.width = `${data.memory}%`;
    }
    if (data.uptime) {
        document.getElementById("uptimeVal").innerText = data.uptime;
    }
}

async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();

        document.getElementById("cpuVal").innerText = `${data.system.cpu_percent}%`;
        document.getElementById("cpuBar").style.width = `${data.system.cpu_percent}%`;

        document.getElementById("memVal").innerText = `${data.system.memory_used_mb} / ${data.system.memory_total_mb} MB`;
        document.getElementById("memBar").style.width = `${data.system.memory_percent}%`;

        document.getElementById("threatsCountVal").innerText = data.threat_summary.total_threats;
        document.getElementById("mitigatedVal").textContent = `${data.active_defense.terminated_pids_count} mitigated`;

        document.getElementById("uptimeVal").innerText = data.uptime;
        document.getElementById("statusVal").innerText = data.status;

        if (data.demo_mode) {
            document.getElementById("demoBadge").style.display = "inline-block";
        }

        const toggle = document.getElementById("autoDefenseToggle");
        const badge = document.getElementById("defenseStatusBadge");
        toggle.checked = data.active_defense.auto_defense;

        if (data.active_defense.auto_defense) {
            badge.className = "badge badge-success";
            badge.innerText = "ACTIVE";
        } else {
            badge.className = "badge badge-warning";
            badge.innerText = "ALERT";
        }

        renderBlockedIPs(data.active_defense.blocked_ips);

        if (!wsConnection || wsConnection.readyState !== WebSocket.OPEN) {
            tryWebSocket();
        }
    } catch (err) {
        document.getElementById("statusVal").innerText = "OFFLINE";
        document.getElementById("statusVal").style.color = "var(--accent-rose)";
    }
}

async function toggleAutoDefense(enabled) {
    try {
        await fetch("/api/defender/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled })
        });
        fetchStatus();
    } catch (err) {
        console.error("Toggle defense error:", err);
    }
}

async function fetchThreats() {
    try {
        const res = await fetch("/api/threats");
        const data = await res.json();
        const tbody = document.getElementById("threatsTableBody");

        if (!data.threats || data.threats.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:2rem;">No threats detected in this session.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.threats.map(t => {
            const sev = t.severity;
            const sevClass = (sev === 'HIGH' || sev === 'CRITICAL') ? 'badge-danger' : (sev === 'MEDIUM' ? 'badge-warning' : 'badge-info');
            const mitBadge = t.auto_mitigated
                ? '<span class="badge badge-success">MITIGATED</span>'
                : '<span class="badge badge-warning">ALERT</span>';

            const targetIP = t.details?.ip || '';
            const targetPID = t.details?.pid || 0;

            let actionBtn = '—';
            if (targetIP) {
                actionBtn = `<button class="btn btn-sm btn-danger" onclick="blockIP('${targetIP}')">Block IP</button>`;
            } else if (targetPID) {
                actionBtn = `<button class="btn btn-sm btn-danger" onclick="killPID(${targetPID})">Kill PID</button>`;
            }

            const detailStr = Object.entries(t.details || {}).map(([k,v]) => `${k}: ${v}`).join(' · ');

            return `<tr>
                <td>${t.timestamp}</td>
                <td><strong>${t.type}</strong></td>
                <td><span class="badge ${sevClass}">${sev}</span></td>
                <td style="font-weight:700; color:var(--accent-rose);">${t.score}/100</td>
                <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${detailStr}">${detailStr}</td>
                <td>${mitBadge}</td>
                <td>${actionBtn}</td>
            </tr>`;
        }).join("");
    } catch (err) {
        console.error("Fetch threats error:", err);
    }
}

async function fetchProcesses() {
    try {
        const res = await fetch("/api/processes?limit=60");
        const data = await res.json();
        allProcesses = data.processes || [];
        renderProcesses(allProcesses);
    } catch (err) {
        console.error("Fetch processes error:", err);
    }
}

function renderProcesses(procs) {
    const tbody = document.getElementById("procTableBody");
    if (!procs.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">No processes found.</td></tr>`;
        return;
    }

    tbody.innerHTML = procs.map(p => {
        const cpuBar = `<div style="display:flex;align-items:center;gap:6px;"><span>${p.cpu}%</span><div style="width:50px;height:3px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;"><div style="height:100%;width:${Math.min(p.cpu, 100)}%;background:${p.cpu > 50 ? 'var(--accent-rose)' : p.cpu > 20 ? 'var(--accent-amber)' : 'var(--accent-emerald)'};border-radius:2px;"></div></div></div>`;
        return `<tr>
            <td><strong>${p.pid}</strong></td>
            <td>${p.name}</td>
            <td>${p.user}</td>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${p.path}">${p.path}</td>
            <td>${cpuBar}</td>
            <td>${p.memory}%</td>
            <td><button class="btn btn-sm btn-danger" onclick="killPID(${p.pid})">Kill</button></td>
        </tr>`;
    }).join("");
}

function filterProcesses() {
    const q = document.getElementById("procSearch").value.toLowerCase();
    const filtered = allProcesses.filter(p => p.name.toLowerCase().includes(q) || p.pid.toString().includes(q));
    renderProcesses(filtered);
}

async function fetchConnections() {
    try {
        const res = await fetch("/api/connections");
        const data = await res.json();
        const tbody = document.getElementById("netTableBody");

        if (!data.connections || data.connections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No active connections.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.connections.map(c => {
            const statusClass = c.status === 'ESTABLISHED' ? 'badge-success' : (c.status === 'SYN_RECV' ? 'badge-danger' : 'badge-info');
            return `<tr>
                <td><span class="badge badge-info">${c.type}</span></td>
                <td>${c.local}</td>
                <td><strong>${c.remote}</strong></td>
                <td><span class="badge ${statusClass}">${c.status}</span></td>
                <td>${c.pid || '—'}</td>
                <td><button class="btn btn-sm btn-danger" onclick="blockIP('${c.remote_ip}')">Block</button></td>
            </tr>`;
        }).join("");
    } catch (err) {
        console.error("Fetch connections error:", err);
    }
}

async function killPID(pid) {
    if (!confirm(`Kill process PID ${pid}?`)) return;

    try {
        const res = await fetch("/api/actions/kill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pid, reason: "Manual Dashboard Action" })
        });
        const data = await res.json();
        showToast(data.message);
        fetchProcesses();
        fetchStatus();
    } catch (err) {
        showToast("Error killing process: " + err, true);
    }
}

async function blockIP(ip) {
    if (!confirm(`Block IP ${ip} in firewall?`)) return;

    try {
        const res = await fetch("/api/actions/block_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip, reason: "Manual Dashboard Action" })
        });
        const data = await res.json();
        showToast(data.message);
        fetchStatus();
    } catch (err) {
        showToast("Error blocking IP: " + err, true);
    }
}

async function unblockIP(ip) {
    try {
        const res = await fetch("/api/actions/unblock_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        showToast(data.message);
        fetchStatus();
    } catch (err) {
        showToast("Error unblocking IP: " + err, true);
    }
}

function manualBlockIP() {
    const ip = document.getElementById("manualBlockIP").value.trim();
    if (ip) blockIP(ip);
}

function renderBlockedIPs(list) {
    const ul = document.getElementById("blockedIPsList");
    if (!list || list.length === 0) {
        ul.innerHTML = `<li class="empty-msg">No blocked IPs.</li>`;
        return;
    }
    ul.innerHTML = list.map(ip => `
        <li>
            <span>🚫 <strong>${ip}</strong></span>
            <button class="btn btn-sm btn-secondary" onclick="unblockIP('${ip}')">Unblock</button>
        </li>
    `).join("");
}

async function fetchLogs() {
    try {
        const res = await fetch("/api/logs?limit=50");
        const data = await res.json();
        const term = document.getElementById("logsTerminal");
        if (data.logs && data.logs.length > 0) {
            term.innerHTML = data.logs.map(l => `<div>${escapeHtml(l)}</div>`).join("");
            term.scrollTop = term.scrollHeight;
        } else {
            term.innerHTML = `<div style="color:var(--text-muted);">No logs recorded yet.</div>`;
        }
    } catch (err) {
        console.error("Fetch logs error:", err);
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 2rem; right: 2rem; z-index: 9999;
        background: ${isError ? 'var(--accent-rose)' : 'var(--accent-emerald)'};
        color: white; padding: 0.75rem 1.25rem; border-radius: 8px;
        font-size: 0.85rem; font-weight: 600; font-family: var(--font-sans);
        box-shadow: 0 8px 30px rgba(0,0,0,0.4);
        animation: slideIn 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
