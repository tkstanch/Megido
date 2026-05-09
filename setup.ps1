$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$pythonBin = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $pythonBin -m megido_security.setup @args
exit $LASTEXITCODE
