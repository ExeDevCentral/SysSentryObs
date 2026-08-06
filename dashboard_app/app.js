// OwlEyeEngine Dashboard Client JS

document.addEventListener("DOMContentLoaded", () => {
    fetchStatus();
    fetchThreats();
    fetchProcesses();
    fetchConnections();
    fetchLogs();

    // Auto-refresh stats every 3 seconds
    setInterval(fetchStatus, 3000);
    setInterval(fetchThreats, 5000);
});

let allProcesses = [];

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

    const selectedBtn = Array.from(document.querySelectorAll(".tab-btn")).find(b => b.getAttribute("onclick").includes(tabId));
    if (selectedBtn) selectedBtn.classList.add("active");

    const targetTab = document.getElementById(`tab-${tabId}`);
    if (targetTab) targetTab.classList.add("active");

    if (tabId === 'processes') fetchProcesses();
    if (tabId === 'network') fetchConnections();
    if (tabId === 'logs') fetchLogs();
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
        document.getElementById("mitigatedVal").innerText = `${data.active_defense.terminated_pids_count} mitigados`;

        document.getElementById("uptimeVal").innerText = data.uptime;
        document.getElementById("statusVal").innerText = data.status;

        // Auto Defense toggle sync
        const toggle = document.getElementById("autoDefenseToggle");
        const badge = document.getElementById("defenseStatusBadge");
        toggle.checked = data.active_defense.auto_defense;

        if (data.active_defense.auto_defense) {
            badge.className = "badge badge-success";
            badge.innerText = "DEFENSA ACTIVA";
        } else {
            badge.className = "badge badge-warning";
            badge.innerText = "SOLO ALERTA";
        }

        renderBlockedIPs(data.active_defense.blocked_ips);
    } catch (err) {
        console.error("Error fetching status:", err);
    }
}

async function toggleAutoDefense(enabled) {
    try {
        const res = await fetch("/api/defender/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: enabled })
        });
        const data = await res.json();
        fetchStatus();
    } catch (err) {
        alert("Error al cambiar estado de defensa activa: " + err);
    }
}

async function fetchThreats() {
    try {
        const res = await fetch("/api/threats");
        const data = await res.json();
        const tbody = document.getElementById("threatsTableBody");

        if (!data.threats || data.threats.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Sin amenazas registradas en la sesión actual.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.threats.map(t => {
            const sevBadge = t.severity === 'HIGH' || t.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning';
            const mitBadge = t.auto_mitigated ? '<span class="badge badge-success">MITIGADO</span>' : '<span class="badge badge-warning">ALERTA</span>';
            const targetIP = t.details.ip || '';
            const targetPID = t.details.pid || 0;

            let actionBtn = '-';
            if (targetIP) {
                actionBtn = `<button class="btn btn-sm btn-danger" onclick="blockIP('${targetIP}')">Bloquear IP</button>`;
            } else if (targetPID) {
                actionBtn = `<button class="btn btn-sm btn-danger" onclick="killPID(${targetPID})">Kill PID</button>`;
            }

            return `
                <tr>
                    <td>${t.timestamp}</td>
                    <td><strong>${t.type}</strong></td>
                    <td><span class="badge ${sevBadge}">${t.severity}</span></td>
                    <td><span style="color: var(--accent-rose); font-weight: bold;">${t.score}/100</span></td>
                    <td><small>${JSON.stringify(t.details)}</small></td>
                    <td>${mitBadge}</td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join("");
    } catch (err) {
        console.error("Error fetching threats:", err);
    }
}

async function fetchProcesses() {
    try {
        const res = await fetch("/api/processes?limit=60");
        const data = await res.json();
        allProcesses = data.processes || [];
        renderProcesses(allProcesses);
    } catch (err) {
        console.error("Error fetching processes:", err);
    }
}

function renderProcesses(procs) {
    const tbody = document.getElementById("procTableBody");
    if (procs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center;">No se encontraron procesos.</td></tr>`;
        return;
    }

    tbody.innerHTML = procs.map(p => `
        <tr>
            <td><strong>${p.pid}</strong></td>
            <td>${p.name}</td>
            <td>${p.user}</td>
            <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${p.path}">${p.path}</td>
            <td>${p.cpu}%</td>
            <td>${p.memory}%</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="killPID(${p.pid})">Kill Process</button>
            </td>
        </tr>
    `).join("");
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
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">Sin conexiones activas de red.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.connections.map(c => `
            <tr>
                <td><span class="badge badge-success">${c.type} (${c.family})</span></td>
                <td>${c.local}</td>
                <td><strong>${c.remote}</strong></td>
                <td>${c.status}</td>
                <td>${c.pid || 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="blockIP('${c.remote_ip}')">Bloquear IP</button>
                </td>
            </tr>
        `).join("");
    } catch (err) {
        console.error("Error fetching connections:", err);
    }
}

async function killPID(pid) {
    if (!confirm(`¿Confirmas finalizar el proceso PID ${pid}?`)) return;

    try {
        const res = await fetch("/api/actions/kill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pid: pid, reason: "Manual User Action via Dashboard" })
        });
        const data = await res.json();
        alert(data.message);
        fetchProcesses();
        fetchStatus();
    } catch (err) {
        alert("Error al finalizar proceso: " + err);
    }
}

async function blockIP(ip) {
    if (!confirm(`¿Confirmas bloquear la IP ${ip} en el Firewall?`)) return;

    try {
        const res = await fetch("/api/actions/block_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, reason: "Manual Block Action via Dashboard" })
        });
        const data = await res.json();
        alert(data.message);
        fetchStatus();
    } catch (err) {
        alert("Error al bloquear IP: " + err);
    }
}

async function unblockIP(ip) {
    try {
        const res = await fetch("/api/actions/unblock_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();
        alert(data.message);
        fetchStatus();
    } catch (err) {
        alert("Error al desbloquear IP: " + err);
    }
}

function manualBlockIP() {
    const ip = document.getElementById("manualBlockIP").value.trim();
    if (ip) blockIP(ip);
}

function renderBlockedIPs(blockedList) {
    const ul = document.getElementById("blockedIPsList");
    if (!blockedList || blockedList.length === 0) {
        ul.innerHTML = `<li class="empty-msg">No hay IPs bloqueadas actualmente.</li>`;
        return;
    }

    ul.innerHTML = blockedList.map(ip => `
        <li>
            <span>🚫 <strong>${ip}</strong></span>
            <button class="btn btn-sm btn-secondary" onclick="unblockIP('${ip}')">Desbloquear</button>
        </li>
    `).join("");
}

async function fetchLogs() {
    try {
        const res = await fetch("/api/logs?limit=40");
        const data = await res.json();
        const term = document.getElementById("logsTerminal");
        if (data.logs && data.logs.length > 0) {
            term.innerHTML = data.logs.map(l => `<div>${l}</div>`).join("");
        } else {
            term.innerHTML = `<div>Sin logs registrados aún en _sentry_log.sys</div>`;
        }
    } catch (err) {
        console.error("Error fetching logs:", err);
    }
}
