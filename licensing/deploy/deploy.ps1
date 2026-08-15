# Build the licensing server for Linux and ship it to the VPS.
# Run from Windows, in the licensing folder:
#
#   .\deploy\deploy.ps1 -Server root@YOUR.IP
#
# Safe to re-run for every update - that's the whole point. The website is
# compiled into the binary, so one file is the entire deployment.

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$Exe = ""   # optional: installer or exe to publish as the download
)

$ErrorActionPreference = "Stop"

# Resolve -Exe against the directory you're standing in, BEFORE the
# Push-Location below moves us into the licensing folder. Without this, a
# relative path like installer\output\netvis-setup.exe is looked for inside
# licensing\ - one level away from where it actually is - and scp fails with
# nothing useful to say.
if ($Exe -ne "") {
    if (-not (Test-Path $Exe)) {
        throw "Can't find $Exe (looked in $(Get-Location)). Build it first with installer\build_installer.bat"
    }
    $Exe = (Resolve-Path $Exe).Path
}

Push-Location (Join-Path $PSScriptRoot "..")

try {
    Write-Host "==> building for linux/amd64" -ForegroundColor Cyan
    # Scoped to this process: pure Go, so no C toolchain is needed to
    # cross-compile from Windows.
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -o licensing-linux .
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }

    Write-Host "==> uploading" -ForegroundColor Cyan
    # Staged through /tmp because /opt/netvis is owned by the service user -
    # a normal login (OVH gives you 'ubuntu', not root) can't scp into it.
    # The move into place happens under sudo below, and is atomic, so a
    # half-uploaded file can never be the one that gets started.
    scp licensing-linux "${Server}:/tmp/licensing.new"
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }

    if ($Exe -ne "") {
        # Keep the original filename: the download button links to
        # netvis-setup.exe, so uploading it as netvis.exe would 404.
        $exeName = Split-Path $Exe -Leaf
        Write-Host "==> publishing $exeName as the download" -ForegroundColor Cyan
        scp $Exe "${Server}:/tmp/$exeName"
        if ($LASTEXITCODE -ne 0) { throw "scp of $exeName failed" }
        ssh $Server "sudo mv /tmp/$exeName /opt/netvis/downloads/$exeName; sudo chown netvis:netvis /opt/netvis/downloads/$exeName"
        if ($LASTEXITCODE -ne 0) { throw "publishing $exeName failed" }
    }

    Write-Host "==> restarting service" -ForegroundColor Cyan
    # Copy the script over and run it by name. Two things this avoids:
    # PowerShell mangling quotes in a multi-line ssh argument, and piping
    # to `bash -s`, which occupies stdin so sudo can't prompt for a
    # password. -t gives sudo a terminal in case it wants one.
    scp (Join-Path $PSScriptRoot "remote-update.sh") "${Server}:/tmp/remote-update.sh"
    if ($LASTEXITCODE -ne 0) { throw "scp of remote-update.sh failed" }

    ssh -t $Server "sed -i 's/\r`$//' /tmp/remote-update.sh; bash /tmp/remote-update.sh"
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "The remote step failed - the reason is printed above." -ForegroundColor Yellow
        Write-Host "If it says /opt/netvis is missing, setup-server.sh hasn't run yet:" -ForegroundColor Yellow
        Write-Host "  scp deploy\setup-server.sh ${Server}:/tmp/" -ForegroundColor Yellow
        Write-Host "  ssh -t $Server 'bash /tmp/setup-server.sh netvis.cc'" -ForegroundColor Yellow
        throw "remote restart failed"
    }

    Remove-Item licensing-linux -ErrorAction SilentlyContinue
    Write-Host "`nDeployed." -ForegroundColor Green
}
finally {
    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
