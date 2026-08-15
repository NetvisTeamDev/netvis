# Generate licence keys on the live server and bring them back here.
#
#   .\deploy\keys.ps1 -Server ubuntu@57.131.137.252 -N 10
#   .\deploy\keys.ps1 -Server ubuntu@57.131.137.252 -N 50 -Note "batch aug" -Out keys.txt
#
# Keys have to be made on the server because that's where licenses.db
# lives - a key generated anywhere else wouldn't exist as far as the
# server is concerned, and would be refused on activation.
#
# Without -Out the keys are printed here; with it they're also saved to a
# file, one per line, ready to paste into Shoppy.

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [int]$N = 10,
    [string]$Note = "",
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"

$cmd = "cd /opt/netvis && sudo -u netvis ./licensing gen -n $N"
if ($Note -ne "") {
    # Strip anything that isn't a plain character before this goes into a
    # remote shell command - a quote or semicolon in the note would
    # otherwise run as part of it.
    $safeNote = $Note -replace '[^A-Za-z0-9 _.-]', ''
    $cmd = $cmd + " -note '" + $safeNote + "'"
}

# 2>/dev/null drops the "N key(s) generated" line, which the server prints
# to stderr - so what comes back is keys and nothing else.
$keys = ssh $Server "$cmd 2>/dev/null"
if ($LASTEXITCODE -ne 0) { throw "key generation failed on the server" }

$keys = @($keys | Where-Object { $_.Trim() -ne "" })
$keys | ForEach-Object { Write-Host $_ }

if ($Out -ne "") {
    $keys | Set-Content -Path $Out -Encoding ASCII
    Write-Host ""
    Write-Host "$($keys.Count) key(s) written to $Out" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "$($keys.Count) key(s) generated." -ForegroundColor Green
}
