# TDD runner: go vet + test (usage: .\rt.ps1 [pkg...])
param([Parameter(ValueFromRemainingArguments=$true)] $pkgs)
if (-not $pkgs) { $pkgs = @('./...') }
$env:GOFLAGS = "-count=1"
go vet @pkgs
if ($LASTEXITCODE -ne 0) { exit 1 }
go test @pkgs
exit $LASTEXITCODE
