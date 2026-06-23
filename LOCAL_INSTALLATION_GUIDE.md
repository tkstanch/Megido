# Megido Local Installation Guide

This guide focuses on the fastest supported ways to **download, install, and launch Megido**.

## Official Install Methods

1. **Docker (recommended for most users)**
2. **Local setup scripts (recommended for developers/security researchers)**
3. **GitHub Releases / source ZIP download**

## Canonical Launch Command

Use `python launch.py` as the standard launch command for local installs.

## Platform Quick-Start Matrix

| Platform | Fastest path | Install command | Launch command |
| --- | --- | --- | --- |
| Windows (PowerShell) | Setup script | `./setup.ps1` | `python launch.py` |
| Windows (CMD) | Setup script | `setup.bat` | `python launch.py` |
| macOS / Linux / BSD | Setup script | `./setup.sh` | `python launch.py` |
| Any platform with Docker | Docker | `docker compose up --build` | No extra command (open `http://localhost:8000`) |

## Platform Prerequisites

Some Megido features depend on system services and tools that are not installed
by the Python setup script.  Install them **before** running `setup.sh` /
`setup.ps1` for the best experience.

### Linux (Debian/Ubuntu)

```bash
# Redis – required for Channels WebSocket layer and Celery background tasks
sudo apt install redis-server
sudo systemctl enable --now redis-server

# nmap – required for the port-scan / advanced scanner module
sudo apt install nmap

# Node.js + npm – required to build the Tailwind/webpack frontend assets
sudo apt install nodejs npm

# Scapy raw-socket capture – requires libpcap
sudo apt install libpcap-dev
# Note: raw-socket operations also require running as root or with CAP_NET_RAW.
```

### macOS

```bash
# Redis, nmap, Node.js via Homebrew
brew install redis nmap node
brew services start redis

# Scapy capture support – libpcap ships with macOS; no extra step needed.
# Note: raw-socket operations may require sudo.
```

### Windows (native Python — without Docker)

Windows native installs have a reduced feature set.  The minimum requirement
steps below give you a working web interface.

1. **Python 3.10+** – download from <https://python.org>.
2. **Redis** – Redis has no official Windows binary.  Use one of:
   - **WSL 2** (recommended): enable WSL 2, install Ubuntu, then
     `sudo apt install redis-server && sudo service redis-server start`.
   - **Memurai** (Windows Redis-compatible server):
     <https://www.memurai.com/> (free for development).
   - Set `USE_IN_MEMORY_CHANNELS=true` in your environment to run without
     Redis.  This disables real-time WebSocket features and Celery workers
     but lets the web UI start.
3. **nmap** – download the Windows installer from <https://nmap.org/download.html>
   and ensure `nmap.exe` is on your `PATH`.
4. **Npcap** – required by Scapy for raw packet capture.  Install from
   <https://npcap.com/>.  Run with administrator privileges for raw-socket
   features.
5. **Node.js + npm** – download from <https://nodejs.org/>.

> **Tip:** For the full feature set on Windows, use
> `docker compose up --build` with Docker Desktop instead of a native install.

### Redis-free mode (any platform)

If Redis is not available, set the environment variable before launching:

```bash
# Linux / macOS
export USE_IN_MEMORY_CHANNELS=true
python launch.py

# Windows PowerShell
$env:USE_IN_MEMORY_CHANNELS = "true"
python launch.py
```

This uses Django Channels' in-memory layer and runs Celery tasks
synchronously.  WebSocket real-time updates will work within a single process
but will not scale across workers.

## Shortest Path (Recommended): Docker

### Prerequisites
- Docker Desktop (Windows/macOS) or Docker Engine (Linux)

### Steps
```bash
git clone https://github.com/tkstanch/Megido.git
cd Megido
docker compose up --build
```

Then open <http://localhost:8000>.

To stop:
```bash
docker compose down
```

## Local Setup Scripts (No Docker)

Use this path if you prefer a native Python environment.

### 1) Download the source

- Option A: clone the repo
  ```bash
  git clone https://github.com/tkstanch/Megido.git
  cd Megido
  ```
- Option B: download ZIP from GitHub and extract it, then `cd` into the extracted folder.

### 2) Run the setup script for your OS

- **Windows PowerShell**
  ```powershell
  ./setup.ps1
  ```
- **Windows CMD**
  ```bat
  setup.bat
  ```
- **macOS / Linux / BSD**
  ```bash
  ./setup.sh
  ```

### 3) Launch Megido

```bash
python launch.py
```

If you are on a headless machine, use web mode explicitly:

```bash
python launch.py web
```

## Releases and Direct Downloads

Megido publishes downloadable release bundles for tagged versions.

- Releases page: <https://github.com/tkstanch/Megido/releases>
- Source ZIP (latest branch snapshot): GitHub **Code → Download ZIP**

After extracting a release/source bundle, run the setup script for your platform and then:

```bash
python launch.py
```

## Advanced Manual Setup (Fallback)

Use this only if setup scripts are not suitable for your environment.

### Linux/macOS manual flow
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
USE_SQLITE=true python manage.py migrate --noinput
python launch.py
```

### Windows manual flow (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
$env:USE_SQLITE = "true"
# Optional: skip Redis requirement for first launch
$env:USE_IN_MEMORY_CHANNELS = "true"
python manage.py migrate --noinput
python launch.py
```

## Troubleshooting

- See [README.md](README.md) for feature and module notes.
- See [DOCKER_TESTING.md](DOCKER_TESTING.md) for Docker-specific behavior.
- See [CROSS_PLATFORM.md](CROSS_PLATFORM.md) for platform abstraction details.
- Open issues at <https://github.com/tkstanch/Megido/issues>.

## Responsible Use

Megido is for authorized educational and security research use only.
Do not test systems without explicit permission.
