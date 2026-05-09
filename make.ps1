param(
    [Parameter(Position = 0)]
    [string]$Target = "setup"
)

switch ($Target.ToLowerInvariant()) {
    "setup"    { python -m megido_security.setup --skip-docker }
    "check"    { $env:USE_SQLITE = "true"; python manage.py check }
    "migrate"  { $env:USE_SQLITE = "true"; python manage.py migrate --noinput }
    "test"     { python -m pytest -q test_*.py }
    "run"      { $env:USE_SQLITE = "true"; python manage.py runserver }
    "launch"   { python launch.py }
    "docker-up" { docker compose up --build }
    default     { throw "Unknown target: $Target" }
}
