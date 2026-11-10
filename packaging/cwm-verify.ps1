$ErrorActionPreference = 'Stop'
$runtime = Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\python.exe'
if (-not (Test-Path -LiteralPath $runtime)) { throw 'Complete packaged runtime missing; reinstall the distribution.' }
& $runtime -I -B -m cwm_verify @args
exit $LASTEXITCODE
