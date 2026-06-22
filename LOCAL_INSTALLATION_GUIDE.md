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
python manage.py migrate --noinput
python launch.py
```

## Troubleshooting

- See [README.md](README.md) for feature and module notes.
- See [DOCKER_TESTING.md](DOCKER_TESTING.md) for Docker-specific behavior.
- Open issues at <https://github.com/tkstanch/Megido/issues>.

## Responsible Use

Megido is for authorized educational and security research use only.
Do not test systems without explicit permission.
