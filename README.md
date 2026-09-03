# 🦉 OwlEyeEngine: The Silent Monitor & Active Defense (v3.0 Global Edition)

![OwlEye Logo](owl_eye.png)

![Cybersecurity Shield](https://img.shields.io/badge/Focus-Cybersecurity-blue?style=for-the-badge&logo=shield)
![Platform Support](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-brightgreen?style=for-the-badge)
![Network](https://img.shields.io/badge/Context-Cisco%20Networks-orange?style=for-the-badge&logo=cisco)
![Active Defense](https://img.shields.io/badge/Defense-Active%20Mitigation-red?style=for-the-badge)
![Dashboard](https://img.shields.io/badge/UI-FastAPI%20Web%20Dashboard-cyan?style=for-the-badge)

```text
    ^...^
   / o o \
   |  Y  |   "Silent flight, 360° vision, total active defense.
    V v V    The predator the intruder never hears... until it strikes."
```

**OwlEyeEngine v3.0** es la evolución global del proyecto de seguridad, inspirado en la naturaleza del búho: un cazador nocturno, silencioso y letal. Este motor combina monitoreo de bajo nivel, detección heurística con puntuación de amenaza (*Threat Scoring*), mitigación activa (*Auto-Kill & IP Blocking*) y un **Panel Web futurista** en tiempo real.

---

## 🚀 Capacidades Principales (Edición Global)

### 1. 🎯 Panel Web de Control e Inspección (Futurista & Glassmorphic)
- **Visualización 360°:** Estado de CPU, Memoria, Uptime y Conexiones activas en tiempo real.
- **Threat Feed Interactivo:** Historial de amenazas detectadas con botones de respuesta rápida ("Kill PID", "Bloquear IP").
- **Filtro estilo `htop`:** Búsqueda rápida de procesos con consumo de recursos.

### 2. 🛡️ Módulo de Defensa Activa (Active Defense)
- **Auto-Kill Proactivo:** Finaliza instantáneamente procesos maliciosos ejecutados desde directorios temporales o sospechosos (`/tmp`, `AppData\Local\Temp`).
- **Bloqueo en Firewall:** Bloquea direcciones IP hostiles mediante `Windows Firewall` (Windows) o `iptables` (Linux) ante barridos o escaneos de puertos (*Port Scanning*).
- **Control Manual o Automático:** Conmutador en tiempo real desde el Dashboard para alternar entre *Modo Alerta* y *Defensa Total*.

### 3. 🧠 Análisis Heurístico Avanzado (v3.0 Engine)
- Detección de patrones anómalos de conexión (Cisco Context & Entry Point Tracking).
- Scoring de amenaza ponderado de 0 a 100 con clasificación de severidad (LOW, MEDIUM, HIGH, CRITICAL).

### 4. 📱 Alertas Nocturnas & Multi-Canal
- Integración automática con **Telegram Bot API** para notificaciones críticas al móvil.
- Exportación estructurada en `_sentry_log.sys` (archivo oculto de sistema).

---

## 🛠️ Arquitectura del Sistema

- `sentry.py`: Orquestador principal del motor (Búho Core).
- `active_defender.py`: Módulo de respuesta proactiva (Mitigación & Firewall).
- `heuristic_analyzer.py`: Cerebro analítico y motor de puntuación de amenazas.
- `web_dashboard.py`: Servidor de API REST en FastAPI para el Dashboard Web.
- `dashboard_app/`: Interfaz gráfica interactiva (HTML5 / Vanilla CSS Cyberpunk / JS).
- `network_monitor.py`: Rastreador de entradas y conexiones de red.
- `process_monitor.py`: Monitoreo de procesos a bajo nivel.
- `hidden_logger.py`: Diario sigiloso con persistencia oculta en SO.

---

## 💻 Instalación Rápida (One-Liner & Docker)

### Opción A: Ejecución Local en Python

```bash
# Clone the repository
git clone https://github.com/ExeDevCentral/OwlEyeEngine.git
cd OwlEyeEngine

# Install requirements
pip install -r requirements.txt

# Run Sentry Engine + Web Dashboard
python sentry.py
```
> Abre tu navegador en **`http://localhost:8000`** para acceder al Panel Web.

### Opción B: Despliegue con Docker Compose (Recomendado)

```bash
docker-compose up -d --build
```

---

## 🤝 Conéctate con el Búho

*"La seguridad no es un producto, es un proceso de vigilancia constante y respuesta letal."*

[GitHub Repository: OwlEyeEngine](https://github.com/ExeDevCentral/OwlEyeEngine.git)

---

## ?? Despliegue en Producci�n

### Modo Demo (Portfolio / Demo en vivo)

Para mostrar el proyecto sin exponer procesos reales del servidor:

```bash
# Local
export OWLEYE_DEMO_MODE=true   # Linux/macOS
$env:OWLEYE_DEMO_MODE="true"   # Windows PowerShell
python sentry.py

# Docker (perfil demo, puerto 8001)
docker compose --profile demo up -d --build
```

### Modo Live (monitoreo real)

```bash
export OWLEYE_DEMO_MODE=false
python sentry.py
```

### Variables de entorno

| Variable | Descripci�n | Default |
|----------|-------------|---------|
| `OWLEYE_PORT` | Puerto del dashboard | `8000` |
| `OWLEYE_DEMO_MODE` | `true` = datos simulados | `false` |
| `SENTRY_TELEGRAM_TOKEN` | Token del bot de Telegram | � |
| `SENTRY_TELEGRAM_CHAT_ID` | Chat ID para alertas | � |

### Rutas

- `/` ? Landing page (portfolio)
- `/dashboard` ? Dashboard interactivo
- `/api/status` ? Estado en tiempo real
- `/api/threats` ? Amenazas heur�sticas
- `/ws/live` ? WebSocket en vivo
- `/health` ? Health check

### Despliegue en un servidor (Docker)

```bash
# Modo demo para portfolio
OWLEYE_DEMO_MODE=true docker compose up -d --build

# Modo live (requiere privilegios para firewall)
docker compose up -d --build
```

### Reverse Proxy (Nginx) ejemplo

```nginx
server {
    listen 80;
    server_name owleye.example.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```
