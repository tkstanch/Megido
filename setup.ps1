Write-Host ""
Write-Host "=== Megido Automated Setup Script (Windows, PowerShell) ==="
Write-Host ""

# Prerequisite Check
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is required! Please install Python 3.12+ first."
    exit 1
}
if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Error "pip is required! Please install pip."
    exit 1
}

# Option to use Docker
$useDocker = Read-Host "Do you want to use Docker? (recommended) [Y/n]"
if ($useDocker -eq "" -or $useDocker -eq "Y" -or $useDocker -eq "y") {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker not found! Please install Docker Desktop for Windows."
        exit 1
    }
    Write-Host "[+] Starting Docker Compose services..."
    docker compose up --build
    exit 0
}

# Virtualenv Setup
if (!(Test-Path "venv")) {
    python -m venv venv
}
.\venv\Scripts\activate

Write-Host "[+] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# ClamAV check
Write-Host "[i] Please ensure ClamAV (clamd.exe) is installed and running on port 3310!"
Write-Host "[i] Download: https://www.clamav.net/downloads"
Pause

# Django Migrate, Collectstatic, Superuser
python manage.py migrate
python manage.py collectstatic --noinput

if (!(Test-Path "db.sqlite3")) {
    Write-Host "[+] Creating Django superuser 'admin' with password 'admin'"
    $commands = @"\nfrom django.contrib.auth import get_user_model\nUser = get_user_model()\nif not User.objects.filter(username='admin').exists():\n    User.objects.create_superuser('admin', 'admin@example.com', 'admin')\n"@
    $commands | python manage.py shell
    Write-Host "[i] Superuser created!"
}

# CEF Browser Setup (optional)
Write-Host ""
$setupCef = Read-Host "Do you want to set up CEF desktop browser integration? [y/N]"
if ($setupCef -eq "y" -or $setupCef -eq "Y") {
    Write-Host ""
    Write-Host "[+] Setting up CEF browser integration..."
    python setup_cef_browser.py --setup-only
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CEF browser setup completed successfully!"
        Write-Host "[i] You can launch it anytime with: .\launch_cef_browser.bat"
    } else {
        Write-Host "[!] CEF browser setup failed, but you can still use the web interface"
    }
}

Write-Host ""
Write-Host "[+] Starting Megido server. Open http://localhost:8000 in your browser, login: admin/admin."
python manage.py runserver
