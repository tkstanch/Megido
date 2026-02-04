#!/bin/bash
set -e

echo ""
echo "=== Megido Automated Setup Script (Linux/macOS) ==="
echo ""

# Step 1: System requirements check
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required! Please install python3."
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip is required! Please install pip for python3."
    exit 1
fi

# Step 2: Option to use Docker
read -p "Do you want to use Docker (recommended)? [Y/n]: " answer
answer=${answer:-Y}

if [[ "$answer" =~ ^[Yy]$ ]]; then
    if ! command -v docker &> /dev/null; then
        echo "Docker not found! Please install Docker and rerun this script."
        exit 1
    fi
    echo ""
    echo "[+] Building and starting services with docker compose..."
    docker compose up --build
    exit 0
fi

# Step 3: Manual Python dependencies
echo ""
echo "[+] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[+] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Step 4: Install/ensure ClamAV
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if ! command -v clamd &> /dev/null; then
        echo "[+] Installing ClamAV (requires sudo)..."
        sudo apt update && sudo apt install -y clamav clamav-daemon
        sudo systemctl enable clamav-daemon
        sudo systemctl start clamav-daemon
    else
        echo "[+] ClamAV daemon found."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v clamd &> /dev/null; then
        echo "[+] Installing ClamAV (requires Homebrew)..."
        if ! command -v brew &> /dev/null; then
            echo "Homebrew is required. Please install Homebrew first."
            exit 1
        fi
        brew install clamav
        sudo mkdir -p /usr/local/var/run/clamav
        sudo clamav-freshclam
        sudo clamd &
    else
        echo "[+] ClamAV daemon found."
    fi
fi

# Step 5: Database & App setup
echo "[+] Running Django migrations..."
python manage.py migrate

echo "[+] Collecting static files..."
python manage.py collectstatic --noinput

if [ ! -f "db.sqlite3" ]; then
    echo "[+] Creating Django superuser (username: admin)"
    echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@example.com', 'admin')" | python manage.py shell
    echo "[i] Superuser 'admin' with password 'admin' has been created."
fi

# Step 6: Run the app
echo ""
echo "[+] Starting Megido locally! Visit http://localhost:8000 in your browser."
python manage.py runserver
